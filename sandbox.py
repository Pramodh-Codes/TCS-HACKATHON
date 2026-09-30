import asyncio
from urllib.parse import urlparse

from playwright.async_api import async_playwright


async def analyze_url(url: str):

    result = {
        "url": url,
        "final_url": None,
        "status": None,
        "title": None,
        "redirects": [],
        "external_domains": [],
        "forms": [],
        "downloads": [],
        "risk_indicators": [],
        "risk_score": 0,
        "verdict": "UNKNOWN",
        "error": None,
    }

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        result["error"] = "Invalid URL"
        return result

    original_domain = parsed.netloc

    try:
        async with async_playwright() as p:

            browser = await p.chromium.launch(
                headless=True
            )

            context = await browser.new_context(
                ignore_https_errors=True
            )

            page = await context.new_page()

            # -------------------------
            # Monitor network requests
            # -------------------------

            async def request_handler(request):

                domain = urlparse(request.url).netloc

                if domain and domain != original_domain:

                    if domain not in result["external_domains"]:
                        result["external_domains"].append(domain)

            page.on("request", request_handler)

            # -------------------------
            # Monitor downloads
            # -------------------------

            async def download_handler(download):

                result["downloads"].append(
                    download.suggested_filename
                )

            page.on("download", download_handler)

            # -------------------------
            # Open URL
            # -------------------------

            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=15000
            )

            if response:
                result["status"] = response.status

            result["final_url"] = page.url

            result["title"] = await page.title()

            # -------------------------
            # Redirect detection
            # -------------------------

            if page.url != url:

                result["redirects"].append({
                    "from": url,
                    "to": page.url
                })

                result["risk_indicators"].append(
                    "URL redirected"
                )

                result["risk_score"] += 20

            # -------------------------
            # External domains
            # -------------------------

            if result["external_domains"]:

                result["risk_indicators"].append(
                    "Page contacted external domains"
                )

                result["risk_score"] += 10

            # -------------------------
            # Form detection
            # -------------------------

            forms = await page.locator("form").all()

            for form in forms:

                inputs = await form.locator("input").all()

                form_info = {
                    "action": await form.get_attribute("action"),
                    "inputs": []
                }

                for inp in inputs:

                    input_type = await inp.get_attribute("type")
                    name = await inp.get_attribute("name")

                    form_info["inputs"].append({
                        "type": input_type,
                        "name": name
                    })

                    if input_type == "password":

                        result["risk_indicators"].append(
                            "Password input detected"
                        )

                        result["risk_score"] += 35

                    elif input_type == "email":

                        result["risk_indicators"].append(
                            "Email input detected"
                        )

                        result["risk_score"] += 15

                result["forms"].append(form_info)

            # -------------------------
            # Download detection
            # -------------------------

            if result["downloads"]:

                result["risk_indicators"].append(
                    "File download detected"
                )

                result["risk_score"] += 30

            # -------------------------
            # Final verdict
            # -------------------------

            result["risk_score"] = min(
                result["risk_score"],
                100
            )

            if result["risk_score"] >= 70:

                result["verdict"] = "HIGH RISK"

            elif result["risk_score"] >= 40:

                result["verdict"] = "SUSPICIOUS"

            else:

                result["verdict"] = "LOW RISK"

            await browser.close()

    except Exception as e:

        result["error"] = str(e)

        result["verdict"] = "ANALYSIS FAILED"

    return result