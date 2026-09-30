#!/usr/bin/env python3
"""
eml_flagger.py - Scan a .eml file and print strings/indicators that are flaggable.

Usage:
    python eml_flagger.py message.eml
    python eml_flagger.py message.eml --json
    python eml_flagger.py message.eml --min-severity medium

Only the Python standard library is used. The email is parsed, never executed
or opened; attachments are inspected by name/type only.
"""

import argparse
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

SEV_ORDER = {"low": 1, "medium": 2, "high": 3}
SEV_SCORE = {"low": 1, "medium": 3, "high": 6}

# --------------------------------------------------------------------------
# Indicator lists (extend freely)
# --------------------------------------------------------------------------
URGENCY = [
    "urgent", "immediately", "act now", "action required", "final notice",
    "last warning", "within 24 hours", "within 48 hours", "account suspended",
    "account will be closed", "account locked", "verify your account",
    "confirm your identity", "unusual activity", "suspicious activity",
    "security alert", "your account has been", "limited time", "expires today",
]
CREDENTIALS = [
    "password", "passcode", "one-time code", "otp", "pin number", "login",
    "log in", "sign in", "credentials", "social security", "ssn",
    "credit card", "card number", "cvv", "bank account", "routing number",
    "verify your", "update your payment", "billing information",
]
MONEY_SCAMS = [
    "gift card", "wire transfer", "western union", "bitcoin", "crypto",
    "wallet address", "lottery", "you have won", "inheritance", "beneficiary",
    "prince", "million dollars", "processing fee", "advance fee",
    "invoice attached", "payment overdue", "refund", "tax refund",
]
THREATS = [
    "legal action", "lawsuit", "arrest", "police", "penalty", "fine",
    "your device is infected", "virus detected", "we have recorded you",
    "compromising", "webcam",
]
GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear client", "dear account holder",
    "dear sir/madam", "dear valued", "dear member",
]
KEYWORD_GROUPS = [
    ("urgency", URGENCY, "medium"),
    ("credential-request", CREDENTIALS, "medium"),
    ("money-scam", MONEY_SCAMS, "medium"),
    ("threat", THREATS, "medium"),
    ("generic-greeting", GENERIC_GREETINGS, "low"),
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in",
    "t.ly", "bl.ink", "s.id",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click",
    "country", "work", "support", "loan", "review", "kim", "men", "date",
    "download", "racing", "stream", "gdn", "cam", "icu", "rest", "monster",
}
DANGEROUS_EXT = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "hta", "lnk", "jar", "msi", "ps1", "dll", "reg", "iso",
    "img", "vhd", "cpl", "apk", "sh",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}
HTML_ATTACH_EXT = {"html", "htm", "shtml", "svg", "xhtml"}
URL_PATH_WORDS = ["login", "signin", "verify", "secure", "update", "account",
                  "password", "confirm", "banking", "wallet", "webscr"]

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'\)\]\}]+""", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class Findings:
    def __init__(self):
        self._seen = set()
        self.items = []

    def add(self, severity, category, flag, evidence=""):
        evidence = str(evidence).strip()
        key = (category, flag, evidence)
        if key in self._seen:
            return
        self._seen.add(key)
        self.items.append({
            "severity": severity,
            "category": category,
            "flag": flag,
            "evidence": evidence[:300],
        })


class LinkParser(HTMLParser):
    """Collects anchors (href + visible text), forms, hidden-text tricks."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []          # (href, text)
        self.has_form = False
        self.password_input = False
        self.hidden_styles = []
        self.scripts = False
        self._href = None
        self._buf = []
        self.text_parts = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        style = a.get("style", "").replace(" ", "").lower()
        if any(s in style for s in ("display:none", "visibility:hidden",
                                     "font-size:0", "opacity:0")):
            self.hidden_styles.append(f"<{tag} style=\"{a.get('style')}\">")
        if tag == "a":
            self._href = a.get("href", "")
            self._buf = []
        elif tag == "form":
            self.has_form = True
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_input = True
        elif tag == "script":
            self.scripts = True
        elif tag == "img" and a.get("src", "").startswith("http"):
            pass

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._buf).split())))
            self._href = None

    def handle_data(self, data):
        self.text_parts.append(data)
        if self._href is not None:
            self._buf.append(data)


def root_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) < 2:
        return host.lower()
    if len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"} \
            and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def addr_domain(addr):
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def get_text_parts(msg):
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        if disp == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", "replace")
        (plain if ctype == "text/plain" else html).append(content)
    return "\n".join(plain), "\n".join(html)


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
def check_headers(msg, f):
    from_hdr = msg.get("From", "")
    disp_name, from_addr = parseaddr(from_hdr)
    from_dom = addr_domain(from_addr)

    if not from_addr:
        f.add("high", "header", "Missing or unparseable From address", from_hdr)

    # Display-name spoofing: "paypal@x.com" <evil@y.com>
    m = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", disp_name or "")
    if m and addr_domain(m.group(0)) != from_dom:
        f.add("high", "header", "Display name contains a different email address",
              f"{disp_name!r} vs <{from_addr}>")

    # Reply-To / Return-Path mismatch
    for hdr in ("Reply-To", "Return-Path"):
        for _, a in getaddresses(msg.get_all(hdr, [])):
            d = addr_domain(a)
            if d and from_dom and root_domain(d) != root_domain(from_dom):
                f.add("medium", "header", f"{hdr} domain differs from From domain",
                      f"From: {from_addr} | {hdr}: {a}")

    # Authentication results
    auth = " ".join(msg.get_all("Authentication-Results", []) +
                    msg.get_all("Received-SPF", [])).lower()
    for mech in ("spf", "dkim", "dmarc"):
        for m in re.finditer(rf"\b{mech}\s*=\s*(\w+)", auth):
            res = m.group(1)
            if res in ("fail", "softfail", "permerror", "temperror"):
                f.add("high" if res == "fail" else "medium", "authentication",
                      f"{mech.upper()} {res}", m.group(0))
            elif res in ("none", "neutral"):
                f.add("low", "authentication", f"{mech.upper()} {res}", m.group(0))
    if re.search(r"\breceived-spf\s*:\s*(fail|softfail)", str(msg).lower()[:20000]):
        f.add("medium", "authentication", "Received-SPF failure header present")
    if not auth.strip():
        f.add("low", "authentication", "No Authentication-Results / Received-SPF header found")

    if not msg.get("Message-ID"):
        f.add("low", "header", "Missing Message-ID header")
    if not msg.get("Date"):
        f.add("low", "header", "Missing Date header")

    # Encoded / non-ASCII sender
    if from_dom and (not from_dom.isascii() or "xn--" in from_dom):
        f.add("high", "header", "Sender domain uses punycode / non-ASCII characters", from_dom)

    if from_dom.split(".")[-1] in SUSPICIOUS_TLDS:
        f.add("medium", "header", "Sender domain uses a frequently abused TLD", from_dom)

    # Bulk header flagged as high priority
    if str(msg.get("X-Priority", "")).strip().startswith("1") or \
            str(msg.get("Importance", "")).lower() == "high":
        f.add("low", "header", "Message marked high priority/importance")

    subject = str(msg.get("Subject", ""))
    return subject


def check_keywords(text, where, f):
    low = text.lower()
    for category, words, sev in KEYWORD_GROUPS:
        for w in words:
            if re.search(rf"(?<!\w){re.escape(w)}(?!\w)", low):
                f.add(sev, f"keyword:{category}", w, f"found in {where}")


def check_url(url, f, context=""):
    raw = url if url.lower().startswith(("http://", "https://")) else "http://" + url
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower()
    except ValueError:
        f.add("medium", "url", "Malformed URL", url)
        return
    if not host:
        return

    if IP_RE.match(host):
        f.add("high", "url", "URL uses a raw IP address", url)
    if "@" in p.netloc:
        f.add("high", "url", "URL contains '@' (credential-style obfuscation)", url)
    if host.startswith("xn--") or ".xn--" in host or not host.isascii():
        f.add("high", "url", "URL uses punycode / non-ASCII hostname (possible homoglyph)", url)
    if root_domain(host) in URL_SHORTENERS or host in URL_SHORTENERS:
        f.add("medium", "url", "URL shortener hides the real destination", url)
    if host.split(".")[-1] in SUSPICIOUS_TLDS:
        f.add("medium", "url", "URL uses a frequently abused TLD", url)
    if url.lower().startswith("http://"):
        f.add("low", "url", "Unencrypted http:// link", url)
    if host.count(".") >= 4:
        f.add("medium", "url", "Excessive subdomains in hostname", url)
    if p.port and p.port not in (80, 443):
        f.add("medium", "url", f"Non-standard port {p.port}", url)
    if len(url) > 200:
        f.add("low", "url", "Very long URL", url[:120] + "...")
    ext = p.path.rsplit(".", 1)[-1].lower() if "." in p.path.rsplit("/", 1)[-1] else ""
    if ext in DANGEROUS_EXT:
        f.add("high", "url", f"URL points to a .{ext} file", url)
    path_hits = [w for w in URL_PATH_WORDS if w in (p.path + p.query).lower()]
    if path_hits:
        f.add("low", "url", "Sensitive keywords in URL path/query: " + ", ".join(path_hits), url)
    if host.count("-") >= 3:
        f.add("low", "url", "Many hyphens in hostname (look-alike pattern)", host)


def check_links(plain, html, f):
    urls = set(URL_RE.findall(plain))

    parser = LinkParser()
    if html:
        try:
            parser.feed(html)
        except Exception:
            f.add("low", "html", "HTML body could not be fully parsed")
        urls.update(URL_RE.findall(html))
        for href, text in parser.links:
            if href.lower().startswith(("http://", "https://", "www.")):
                urls.add(href)
            if href.lower().startswith("javascript:"):
                f.add("high", "html", "Link uses javascript: scheme", href)
            # Visible text looks like a URL but points elsewhere
            m = URL_RE.search(text)
            if m and href.lower().startswith(("http", "www")):
                shown = urlparse(m.group(0) if m.group(0).startswith("http")
                                 else "http://" + m.group(0)).hostname or ""
                real = urlparse(href if href.startswith("http")
                                else "http://" + href).hostname or ""
                if shown and real and root_domain(shown) != root_domain(real):
                    f.add("high", "html", "Link text domain differs from actual destination",
                          f"shown: {shown} -> actual: {real}")
        if parser.has_form:
            f.add("medium", "html", "HTML form embedded in email body")
        if parser.password_input:
            f.add("high", "html", "Password input field embedded in email body")
        if parser.scripts:
            f.add("medium", "html", "<script> tag in email body")
        for h in parser.hidden_styles[:5]:
            f.add("medium", "html", "Hidden content via CSS", h)

    for u in sorted(urls):
        check_url(u.rstrip(".,;:!?"), f)
    return parser


def check_attachments(msg, f):
    for part in msg.walk():
        name = part.get_filename()
        if not name:
            continue
        low = name.lower()
        ext = low.rsplit(".", 1)[-1] if "." in low else ""
        ctype = part.get_content_type()

        if ext in DANGEROUS_EXT:
            f.add("high", "attachment", f"Executable/script attachment (.{ext})", name)
        elif ext in MACRO_EXT:
            f.add("high", "attachment", f"Macro-enabled Office attachment (.{ext})", name)
        elif ext in HTML_ATTACH_EXT:
            f.add("medium", "attachment", f"HTML/SVG attachment (.{ext}) - common phishing vector", name)
        elif ext in ARCHIVE_EXT:
            f.add("medium", "attachment", f"Archive attachment (.{ext}) can hide payloads", name)

        if re.search(r"\.\w{2,5}\.(?:%s)$" % "|".join(sorted(DANGEROUS_EXT)), low):
            f.add("high", "attachment", "Double file extension", name)
        if re.search(r"\s{5,}", name) or "\u202e" in name:
            f.add("high", "attachment", "Filename uses padding or right-to-left override trick", repr(name))
        if ext == "pdf" and ctype != "application/pdf":
            f.add("medium", "attachment", "Filename extension does not match declared MIME type",
                  f"{name} ({ctype})")
        if ext in ("doc", "docx", "xls", "xlsx", "pdf") and \
                re.search(r"(invoice|payment|receipt|statement|remittance|purchase.?order)", low):
            f.add("low", "attachment", "Financial-themed document name", name)


def check_body_misc(subject, plain, html_parser, f):
    body_text = plain
    if not body_text.strip() and html_parser and html_parser.text_parts:
        body_text = " ".join(html_parser.text_parts)

    check_keywords(subject, "subject", f)
    check_keywords(body_text, "body", f)

    if re.match(r"^\s*(re|fw|fwd):", subject, re.I) and not \
            re.search(r"(^|\n)>+", body_text):
        f.add("low", "content", "Subject fakes a reply/forward (Re:/Fwd:) with no quoted thread", subject)

    if subject.isupper() and len(subject) > 8:
        f.add("low", "content", "Subject is ALL CAPS", subject)

    if len(body_text.strip()) < 40 and html_parser and html_parser.links:
        f.add("medium", "content", "Very short body containing only links")

    if re.search(r"[\u0400-\u04FF\u0370-\u03FF]", body_text) and re.search(r"[A-Za-z]{3,}", body_text):
        f.add("medium", "content", "Mixed Latin + Cyrillic/Greek characters (possible homoglyphs)")

    if re.search(r"[\u200b\u200c\u200d\u2060\ufeff]", body_text):
        f.add("medium", "content", "Zero-width characters in body (filter evasion)")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def analyze(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    f = Findings()
    subject = check_headers(msg, f)
    plain, html = get_text_parts(msg)
    parser = check_links(plain, html, f)
    check_attachments(msg, f)
    check_body_misc(subject, plain, parser if html else None, f)

    items = sorted(f.items, key=lambda x: (-SEV_ORDER[x["severity"]], x["category"]))
    score = sum(SEV_SCORE[i["severity"]] for i in items)
    verdict = ("likely malicious" if score >= 20 else
               "suspicious" if score >= 8 else
               "low risk" if score > 0 else "no indicators found")
    return {
        "file": path,
        "from": str(msg.get("From", "")),
        "subject": subject,
        "score": score,
        "verdict": verdict,
        "flags": items,
    }


def main():
    ap = argparse.ArgumentParser(description="Flag suspicious indicators in a .eml file.")
    ap.add_argument("eml", help="path to .eml file")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                    help="hide flags below this severity")
    args = ap.parse_args()

    try:
        result = analyze(args.eml)
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.eml}")
    except Exception as e:
        sys.exit(f"error: could not parse {args.eml}: {e}")

    floor = SEV_ORDER[args.min_severity]
    result["flags"] = [i for i in result["flags"] if SEV_ORDER[i["severity"]] >= floor]

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    print(f"File    : {result['file']}")
    print(f"From    : {result['from']}")
    print(f"Subject : {result['subject']}")
    print(f"Score   : {result['score']}  ->  {result['verdict']}")
    print("-" * 70)
    if not result["flags"]:
        print("No flaggable strings found.")
        return
    for i in result["flags"]:
        print(f"[{i['severity'].upper():6}] {i['category']}: {i['flag']}")
        if i["evidence"]:
            print(f"         -> {i['evidence']}")


if __name__ == "__main__":
    main()
