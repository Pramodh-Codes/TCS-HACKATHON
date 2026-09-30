#!/usr/bin/env python3
"""
eml_flagger_v2.py - Offline phishing analyzer with an India-focused rule set.

v2 adds:
  1. Indian-context detection  (KYC / PAN / Aadhaar / UPI / tax-refund / SIM /
     courier lures, Hindi + Hinglish phrases, UPI IDs, WhatsApp callback scams)
  2. Look-alike brand detection (homoglyphs, typo-squats, brand names hidden in
     unrelated domains, display-name impersonation)
  3. Attack-type classification with a plain-language explanation,
     MITRE ATT&CK mapping and "what to do" advice

Usage:
    python eml_flagger_v2.py message.eml
    python eml_flagger_v2.py message.eml --json
    python eml_flagger_v2.py message.eml --min-severity medium

Only the Python standard library is used. The email is parsed, never executed
or opened; attachments are inspected by name/type only.
"""

import argparse
import json
import re
import sys
import textwrap
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

# ---- v2: India-specific lures ---------------------------------------------
INDIA_LURES = [
    "kyc expired", "kyc update", "update your kyc", "complete your kyc",
    "kyc verification", "kyc pending", "pan card will be blocked",
    "link your pan", "pan and aadhaar", "aadhaar update", "aadhaar suspended",
    "aadhar update", "upi pin", "share your upi", "income tax refund",
    "it refund", "itr refund", "tax refund of rs", "account will be blocked",
    "account will be suspended", "net banking will be blocked",
    "netbanking will be blocked", "sim will be blocked", "sim card will be blocked",
    "electricity will be disconnected", "power will be disconnected",
    "parcel is held", "parcel held", "customs duty", "delivery failed",
    "redelivery fee", "could not be delivered", "digital arrest", "cbi officer",
    "narcotics", "reward points will expire", "reward points expire",
    "credit card reward", "work from home", "part time job", "earn daily",
    "lucky draw", "kbc lottery", "you have been selected",
]
INDIA_CONTEXT = [
    "kyc", "aadhaar", "aadhar", "upi", "pan card", "fastag", "epfo", "itr",
]
HINDI_LURES = [
    "turant", "khata band", "khata block", "band ho jayega", "block ho jayega",
    "aapka khata", "inaam", "apna kyc", "jaldi karein",
    "तुरंत", "खाता बंद", "खाता ब्लॉक", "केवाईसी", "आधार", "पैन कार्ड",
    "बंद हो जाएगा", "ब्लॉक हो जाएगा", "इनाम",
]

KEYWORD_GROUPS = [
    ("urgency", URGENCY, "medium"),
    ("credential-request", CREDENTIALS, "medium"),
    ("money-scam", MONEY_SCAMS, "medium"),
    ("threat", THREATS, "medium"),
    ("generic-greeting", GENERIC_GREETINGS, "low"),
    ("india-lure", INDIA_LURES, "medium"),
    ("india-context", INDIA_CONTEXT, "low"),
    ("hindi-lure", HINDI_LURES, "medium"),
]

# ---- v2: brands commonly impersonated (extend freely) ----------------------
# tokens : words that identify the brand inside a domain / display name
# domains: the brand's official domains (subdomains are accepted automatically)
BRANDS = {
    "SBI": {"tokens": ["sbi", "onlinesbi", "statebankofindia"],
            "domains": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com",
                        "sbilife.co.in", "sbi.bank.in", "sbi.in"]},
    "HDFC Bank": {"tokens": ["hdfc", "hdfcbank"],
                  "domains": ["hdfcbank.com", "hdfcbank.net", "hdfc.com", "hdfclife.com"]},
    "ICICI Bank": {"tokens": ["icici", "icicibank"],
                   "domains": ["icicibank.com", "icicidirect.com", "iciciprulife.com",
                               "icicilombard.com"]},
    "Axis Bank": {"tokens": ["axisbank"], "domains": ["axisbank.com", "axis.bank.in"]},
    "Kotak": {"tokens": ["kotak", "kotakbank"], "domains": ["kotak.com", "kotakbank.com"]},
    "Paytm": {"tokens": ["paytm"], "domains": ["paytm.com", "paytm.in", "paytmbank.com"]},
    "PhonePe": {"tokens": ["phonepe"], "domains": ["phonepe.com"]},
    "NPCI / UPI": {"tokens": ["npci"], "domains": ["npci.org.in"]},
    "Income Tax Dept": {"tokens": ["incometax", "incometaxindia", "incometaxindiaefiling"],
                        "domains": ["incometax.gov.in", "incometaxindiaefiling.gov.in"]},
    "UIDAI (Aadhaar)": {"tokens": ["uidai"], "domains": ["uidai.gov.in"]},
    "EPFO": {"tokens": ["epfo", "epfindia"], "domains": ["epfindia.gov.in", "epfo.gov.in"]},
    "IRCTC": {"tokens": ["irctc"], "domains": ["irctc.co.in"]},
    "India Post": {"tokens": ["indiapost"], "domains": ["indiapost.gov.in"]},
    "Amazon": {"tokens": ["amazon"],
               "domains": ["amazon.in", "amazon.com", "amazonses.com", "amazonaws.com",
                           "amazon-adsystem.com", "media-amazon.com"]},
    "Flipkart": {"tokens": ["flipkart"], "domains": ["flipkart.com"]},
    "PayPal": {"tokens": ["paypal"],
               "domains": ["paypal.com", "paypal.me", "paypal-communication.com",
                           "paypalobjects.com"]},
    "Microsoft": {"tokens": ["microsoft", "office365"],
                  "domains": ["microsoft.com", "microsoftonline.com", "office.com",
                              "office365.com", "outlook.com", "live.com"]},
    "Google": {"tokens": ["google", "gmail"],
               "domains": ["google.com", "gmail.com", "googlemail.com",
                           "googleusercontent.com", "gstatic.com", "googleapis.com"]},
    "Apple": {"tokens": ["apple", "icloud"], "domains": ["apple.com", "icloud.com"]},
    "Netflix": {"tokens": ["netflix"], "domains": ["netflix.com", "nflxso.net"]},
    "Facebook / Meta": {"tokens": ["facebook"],
                        "domains": ["facebook.com", "facebookmail.com", "fb.com", "meta.com"]},
    "LinkedIn": {"tokens": ["linkedin"], "domains": ["linkedin.com"]},
    "DHL": {"tokens": ["dhl"], "domains": ["dhl.com"]},
    "FedEx": {"tokens": ["fedex"], "domains": ["fedex.com"]},
    "Blue Dart": {"tokens": ["bluedart"], "domains": ["bluedart.com"]},
    "Jio": {"tokens": ["jio"], "domains": ["jio.com", "ril.com"]},
    "Airtel": {"tokens": ["airtel"], "domains": ["airtel.in", "airtel.com"]},
    "TCS": {"tokens": ["tcs"], "domains": ["tcs.com"]},
}

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
        self.brands = set()      # v2: brands the email seems to impersonate

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
# v2: brand impersonation helpers
# --------------------------------------------------------------------------
def levenshtein(a, b):
    """Edit distance between two strings."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LEET = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e",
                       "5": "s", "4": "a", "7": "t", "$": "s"})


def canon(s):
    """Fold look-alike characters so paypa1 == paypal and arnazon == amazon."""
    return s.lower().replace("rn", "m").replace("vv", "w").translate(_LEET)


def is_legit(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def token_matches(seg, token):
    return (seg == token
            or (len(token) >= 5 and seg.startswith(token))
            or (len(token) >= 8 and token in seg))


def brand_check(host, f, where, evidence=None):
    """Flag hosts that imitate a known brand but are not its official domain."""
    host = (host or "").lower().strip(".")
    if not host or IP_RE.match(host) or "." not in host:
        return set()
    evidence = evidence or host
    core = root_domain(host).split(".")[0]
    base = host.rsplit(".", 1)[0]
    segs = [s for s in re.split(r"[.\-_]+", base) if s]
    segs += [s for s in re.split(r"[.\-_0-9]+", base) if s]      # hdfc2024 -> hdfc
    hits = set()
    for name, b in BRANDS.items():
        if is_legit(host, b["domains"]):
            continue
        cores = {d.split(".")[0] for d in b["domains"]} | {t for t in b["tokens"] if len(t) >= 5}
        kind = None
        for c in cores:
            if len(c) < 5:
                continue
            if core == c:
                kind = "brand name on an unofficial domain/TLD"
                break
            if canon(core) == canon(c):
                kind = "homoglyph look-alike of the brand"
                break
            if abs(len(core) - len(c)) <= 1 and levenshtein(core, c) == 1:
                kind = "typo-squat of the brand"
                break
        if not kind and any(token_matches(s, t) or token_matches(canon(s), canon(t))
                            for s in segs for t in b["tokens"]):
            kind = "brand name embedded in an unrelated domain"
        if kind:
            hits.add(name)
            f.brands.add(name)
            sev = "medium" if kind.startswith("brand name on") else "high"
            f.add(sev, "brand-impersonation",
                  f"Possible {name} impersonation ({where}): {kind}",
                  f"{evidence}  [official: {b['domains'][0]}]")
    return hits


def check_display_brand(disp_name, from_dom, f):
    """Display name says 'HDFC Bank' but the sending domain is not HDFC's."""
    if not disp_name or not from_dom:
        return
    words = re.findall(r"[a-z0-9]+", disp_name.lower())
    for name, b in BRANDS.items():
        if is_legit(from_dom, b["domains"]):
            continue
        if any(token_matches(w, t) for w in words for t in b["tokens"]):
            f.brands.add(name)
            f.add("high", "brand-impersonation",
                  f"Display name claims to be {name} but sender domain is not official",
                  f"{disp_name!r} sent from {from_dom}  [official: {b['domains'][0]}]")


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

    # v2: brand impersonation in sender / display name / reply-to
    check_display_brand(disp_name, from_dom, f)
    brand_check(from_dom, f, "sender", f"From: {from_addr}")
    for _, a in getaddresses(msg.get_all("Reply-To", [])):
        brand_check(addr_domain(a), f, "reply-to", f"Reply-To: {a}")

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
            if w.isascii():
                hit = re.search(rf"(?<!\w){re.escape(w)}(?!\w)", low)
            else:                       # Hindi/Devanagari: plain substring match
                hit = w in low
            if hit:
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

    brand_check(host, f, "link", url)
    if host in ("wa.me", "api.whatsapp.com", "chat.whatsapp.com"):
        f.add("medium", "url", "WhatsApp link (common in Indian scam campaigns)", url)
    if host in ("t.me", "telegram.me"):
        f.add("medium", "url", "Telegram link (common in job/investment scams)", url)

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

    # v2: India-specific patterns
    m = re.search(r"(?:call|contact|whatsapp|dial|sms)[^.\n]{0,40}?(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b",
                  body_text, re.I)
    if m:
        f.add("medium", "content",
              "Asks you to call/WhatsApp a mobile number (callback-scam pattern)", m.group(0))
    m = re.search(r"\b[\w.\-]{2,}@(?:ok(?:axis|hdfcbank|sbi|icici)|ybl|ibl|axl|apl|paytm|upi|ptsbi|pthdfc|ptyes)\b",
                  body_text, re.I)
    if m:
        f.add("medium", "content", "Contains a UPI payment ID (VPA)", m.group(0))


# --------------------------------------------------------------------------
# v2: attack-type classification + plain-language explanation
# --------------------------------------------------------------------------
# Each attack type is recognised from the flags already raised. "triggers" are
# matched against "<category> <flag text>". MITRE IDs are an approximate mapping.
ATTACK_TYPES = {
    "Credential harvesting": {
        "triggers": ["credential-request", "Password input", "HTML form",
                     "Link text domain differs", "Sensitive keywords in URL", "javascript:"],
        "meaning": "It is trying to make you type a password, OTP or card details "
                   "into a page the attacker controls.",
        "mitre": "T1566.002 / T1598.003",
        "advice": "Do not click the link or enter any details; open the real site by typing its address yourself.",
    },
    "Brand impersonation / spoofing": {
        "triggers": ["brand-impersonation", "Display name", "Reply-To domain differs",
                     "Return-Path domain differs", "authentication", "punycode"],
        "meaning": "The sender pretends to be a trusted company or person, "
                   "but the technical details do not match.",
        "mitre": "T1656",
        "advice": "Verify through the organisation's official app or phone number, not through this email.",
    },
    "Malware delivery": {
        "triggers": ["Executable/script attachment", "Macro-enabled", "Double file extension",
                     "HTML/SVG attachment", "Archive attachment", "URL points to a", "<script>"],
        "meaning": "It tries to get you to open a file or link that installs malicious software.",
        "mitre": "T1566.001 / T1204.002",
        "advice": "Do not open the attachment or link; report it to your IT/security team.",
    },
    "Financial / payment fraud": {
        "triggers": ["money-scam", "UPI payment ID", "Financial-themed document"],
        "meaning": "It tries to get you to send money or approve a payment.",
        "mitre": "T1657",
        "advice": "Never approve UPI requests or pay 'fees' to unknown parties; check with the payee directly.",
    },
    "KYC / government-service scam (India)": {
        "triggers": ["india-lure", "hindi-lure"],
        "meaning": "It uses fear about KYC, PAN/Aadhaar, tax refunds, SIM or utility "
                   "disconnection to rush you into acting.",
        "mitre": "T1598",
        "advice": "Banks and government bodies do not ask for KYC, OTP or UPI PIN by email; log in via the official app.",
    },
    "Callback / WhatsApp scam": {
        "triggers": ["call/WhatsApp", "WhatsApp link", "Telegram link"],
        "meaning": "It moves you off email to a phone number or chat app, "
                   "where scammers can pressure you live.",
        "mitre": "T1566.004",
        "advice": "Do not call or message the number; look up the official helpline yourself.",
    },
    "Threat / extortion": {
        "triggers": ["keyword:threat"],
        "meaning": "It uses threats (legal action, arrest, leaked data) to scare you into complying.",
        "mitre": "-",
        "advice": "Ignore the threats and do not pay; report the email.",
    },
}


def classify(items, brands, score):
    """Turn the raw flags into an attack type, an explanation and advice."""
    if score < 8:
        return {"primary": "No clear attack pattern", "also": [], "brands": sorted(brands),
                "explanation": "Not enough independent warning signs to call this a phishing attempt.",
                "evidence": [], "mitre": [], "advice": []}

    scored = []
    for tname, t in ATTACK_TYPES.items():
        matched = [i for i in items
                   if any(trig.lower() in f"{i['category']} {i['flag']}".lower()
                          for trig in t["triggers"])]
        pts = sum(SEV_SCORE[i["severity"]] for i in matched)
        if pts >= 6:
            scored.append((pts, tname, matched))
    scored.sort(key=lambda x: -x[0])

    if not scored:
        return {"primary": "Suspicious (no single attack type stands out)", "also": [],
                "brands": sorted(brands),
                "explanation": "Several warning signs were found but they do not fit one known pattern.",
                "evidence": [], "mitre": [], "advice": ["Treat with caution and verify the sender independently."]}

    _, primary, matched = scored[0]
    others = [n for _, n, _ in scored[1:3]]
    top = sorted(matched, key=lambda i: (-SEV_ORDER[i["severity"]],
                                         i["category"] == "authentication"))[:3]
    evidence = [f"{i['flag']}" + (f" - {i['evidence']}" if i["evidence"] else "") for i in top]

    text = f"Most likely: {primary.lower()}. {ATTACK_TYPES[primary]['meaning']}"
    if brands:
        text += f" It appears to impersonate {', '.join(sorted(brands))}."
    if any(i["category"] == "keyword:urgency" for i in items):
        text += " It also uses urgency wording to rush you."

    advice, mitre = [], []
    for name in [primary] + others:
        a, m = ATTACK_TYPES[name]["advice"], ATTACK_TYPES[name]["mitre"]
        if a not in advice:
            advice.append(a)
        if m != "-" and m not in mitre:
            mitre.append(m)
    return {"primary": primary, "also": others, "brands": sorted(brands),
            "explanation": text, "evidence": evidence, "mitre": mitre, "advice": advice[:3]}


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
    verdict = ("Highly malicious" if score >= 75 else
               "likely malicious" if score >= 50 else
               "suspicious" if score >= 30 else
               "potentially risky" if score >= 10 else
               "low risk" if score > 0 else "no indicators found")
    classification = classify(items, f.brands, score)
    return {
        "file": path,
        "from": str(msg.get("From", "")),
        "subject": subject,
        "score": score,
        "verdict": verdict,
        "classification": classification,
        "flags": items,
    }


def main():
    ap = argparse.ArgumentParser(description="Flag suspicious indicators in a .eml file.")
    ap.add_argument("eml", help="path to .eml file")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                    help="hide flags below this severity")
    args = ap.parse_args()
    try:                                   # keep Hindi text printable on Windows
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

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
    c = result["classification"]
    print("=" * 70)
    also = f"  (also: {', '.join(c['also'])})" if c["also"] else ""
    print(f"ATTACK TYPE : {c['primary']}{also}")
    if c["brands"]:
        print(f"IMPERSONATES: {', '.join(c['brands'])}")
    wrap = lambda t, ind: textwrap.fill(t, 90, initial_indent=ind, subsequent_indent=ind + "   ")
    print(wrap("SUMMARY     : " + c["explanation"], ""))
    if c["evidence"]:
        print("KEY EVIDENCE:")
        for n, e in enumerate(c["evidence"], 1):
            print(wrap(f"{n}. {e}", "   "))
    if c["mitre"]:
        print(f"MITRE ATT&CK: {', '.join(c['mitre'])} (approximate mapping)")
    if c["advice"]:
        print("WHAT TO DO  :")
        for a in c["advice"]:
            print(wrap("- " + a, "   "))
    print("=" * 70)
    print("ALL FLAGS")
    if not result["flags"]:
        print("No flaggable strings found.")
        return
    for i in result["flags"]:
        print(f"[{i['severity'].upper():6}] {i['category']}: {i['flag']}")
        if i["evidence"]:
            print(f"         -> {i['evidence']}")


if __name__ == "__main__":
    main()
