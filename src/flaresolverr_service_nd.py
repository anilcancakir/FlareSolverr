import logging
import platform
import sys
import time
import asyncio
from datetime import timedelta
from urllib.parse import unquote, urlparse
from typing import List
from nodriver import Browser, Tab
from sessions_nd import SessionsStorage

import utils
from dtos import (
    STATUS_ERROR,
    STATUS_OK,
    ChallengeResolutionResultT,
    ChallengeResolutionT,
    V1RequestBase,
    V1ResponseBase,
)

# from sessions import SessionsStorage

ACCESS_DENIED_TITLES = [
    # Cloudflare
    "Access denied",
    # Cloudflare http://bitturk.net/ Firefox
    "Attention Required! | Cloudflare",
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    "div.cf-error-title span.cf-code-label span",
    # Cloudflare http://bitturk.net/ Firefox
    "#cf-error-details div.cf-error-overview h1",
]
CHALLENGE_TITLES = [
    # Cloudflare
    "Just a moment...",
    # DDoS-GUARD
    "DDoS-Guard",
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    "#cf-challenge-running",
    ".ray_id",
    ".attack-box",
    "#cf-please-wait",
    "#challenge-spinner",
    "#trk_jschal_js",
    "#turnstile-wrapper",
    ".lds-ring",
    ".loading-spinner",
    ".main-wrapper",
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    "td.info #js_info",
    # Fairlane / pararius.com
    "div.vc div.text-box h2",
]
SHORT_TIMEOUT = 2
SESSIONS_STORAGE = SessionsStorage()


# TO-DO: See if still necessary. Keeping it for now but nodriver already
#        checks for chromium binaries and exit if no candidate is available
async def test_browser_installation_nd():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None:
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == "":
        logging.error("Chrome / Chromium version not detected!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = await utils.get_user_agent_nd()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


async def controller_v1_endpoint_nd(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = await _controller_v1_handler_nd(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()

    logging.debug(f"Response => POST /v1 body: {utils.object_to_dict_truncated(res)}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


async def _controller_v1_handler_nd(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or req.maxTimeout < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == "sessions.create":
        res = await _cmd_sessions_create_nd(req)
    elif req.cmd == "sessions.list":
        res = _cmd_sessions_list_nd()
    elif req.cmd == "sessions.destroy":
        res = await _cmd_sessions_destroy_nd(req)
    elif req.cmd == "request.get":
        res = await _cmd_request_get_nd(req)
    elif req.cmd == "request.post":
        res = await _cmd_request_post_nd(req)
    elif req.cmd == "sessions.update":
        res = await _cmd_sessions_update_nd(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


async def _cmd_request_get_nd(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception(
            "Request parameter 'url' is mandatory in 'request.get' command."
        )
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning(
            "Request parameter 'returnRawHtml' was removed in FlareSolverr v2."
        )
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = await _resolve_challenge_nd(req, "GET")
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


async def _cmd_request_post_nd(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception(
            "Request parameter 'postData' is mandatory in 'request.post' command."
        )
    if req.returnRawHtml is not None:
        logging.warning(
            "Request parameter 'returnRawHtml' was removed in FlareSolverr v2."
        )
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = await _resolve_challenge_nd(req, "POST")
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


async def _cmd_sessions_create_nd(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = await SESSIONS_STORAGE.create(
        session_id=req.session, proxy=req.proxy
    )
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase(
            {
                "status": STATUS_OK,
                "message": "Session already exists.",
                "session": session_id,
            }
        )

    return V1ResponseBase(
        {
            "status": STATUS_OK,
            "message": "Session created successfully.",
            "session": session_id,
        }
    )


def _cmd_sessions_list_nd() -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({"status": STATUS_OK, "message": "", "sessions": session_ids})


async def _cmd_sessions_destroy_nd(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = await SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase(
        {"status": STATUS_OK, "message": "The session has been removed."}
    )


async def _cmd_sessions_update_nd(req: V1RequestBase) -> V1ResponseBase:
    """Update session with additional cookies (merge mode)"""
    session_id = req.session

    if not session_id:
        raise Exception("Session ID is required.")

    if not SESSIONS_STORAGE.exists(session_id):
        raise Exception("The session doesn't exist.")

    session = SESSIONS_STORAGE.sessions[session_id]
    driver = session.driver

    # Ensure we have an active tab for cookie operations
    tab = await driver.get("about:blank")

    # Get existing cookies (returns list of dicts with requests_cookie_format=True)
    existing_cookies = await driver.cookies.get_all(requests_cookie_format=True)

    # Merge: existing + new (new overrides same name+domain)
    if req.cookies and len(req.cookies) > 0:
        cookie_map = {}

        # Add existing cookies to map
        for c in existing_cookies:
            # Handle both dict and Cookie object
            if isinstance(c, dict):
                name = c.get('name', '')
                domain = c.get('domain', '')
            else:
                name = getattr(c, 'name', '')
                domain = getattr(c, 'domain', '')
            key = f"{name}:{domain}"
            cookie_map[key] = c

        # Add/override with new cookies
        for c in req.cookies:
            key = f"{c['name']}:{c.get('domain', '')}"
            cookie_map[key] = c

        # Convert to CookieParam and set
        cookie_params = []
        for c in cookie_map.values():
            if isinstance(c, dict):
                cookie_params.append(
                    utils.nd.cdp.network.CookieParam(
                        name=c["name"],
                        value=c["value"],
                        path=c.get("path", "/"),
                        domain=c.get("domain", ""),
                    )
                )
            else:
                cookie_params.append(
                    utils.nd.cdp.network.CookieParam(
                        name=c.name,
                        value=c.value,
                        path=getattr(c, 'path', '/'),
                        domain=getattr(c, 'domain', ''),
                    )
                )

        await driver.cookies.set_all(cookie_params)

    # Get updated cookies for response
    final_cookies = await driver.cookies.get_all(requests_cookie_format=True)

    # Close the tab websocket to allow reuse
    await tab.aclose()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session updated successfully.",
        "session": session_id,
        "cookies": final_cookies,
    })


async def _resolve_challenge_nd(
    req: V1RequestBase, method: str
) -> ChallengeResolutionT:
    timeout = req.maxTimeout / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = (
                timedelta(minutes=req.session_ttl_minutes)
                if req.session_ttl_minutes
                else None
            )
            session, fresh = await SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(
                    f"new session created to perform the request (session_id={session_id})"
                )
            else:
                logging.debug(
                    f"existing session is used to perform the request (session_id={session_id}, "
                    f"lifetime={str(session.lifetime())}, ttl={str(ttl)})"
                )

            driver = session.driver
        else:
            driver = await utils.get_webdriver_nd(req.proxy)
            logging.debug(
                "New instance of chromium has been created to perform the request"
            )
        return await asyncio.wait_for(
            _evil_logic_nd(req, driver, method), timeout=timeout
        )
    except TimeoutError:
        raise Exception(
            f"Error solving the challenge. Timeout after {timeout} seconds."
        )
    except Exception as e:
        raise Exception("Error solving the challenge. " + str(e).replace("\n", "\\n"))
    finally:
        if not req.session and driver is not None:
            await utils.after_run_cleanup(driver=driver)
            logging.debug("A used instance of chromium has been destroyed")


async def _evil_logic_nd(
    req: V1RequestBase, driver: Browser, method: str
) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # Storage for captured response data
    captured_response_headers = {}
    captured_status_code = 200
    captured_response_url = None
    network_enabled = False

    def on_response_received(event: utils.nd.cdp.network.ResponseReceived):
        nonlocal captured_response_headers, captured_status_code, captured_response_url
        # Only capture for document type (main page request)
        if event.type_ == utils.nd.cdp.network.ResourceType.DOCUMENT:
            # Track redirects - log if URL changed
            if captured_response_url is not None and captured_response_url != event.response.url:
                logging.debug(f"[REDIRECT] {captured_response_url} -> {event.response.url}")
            captured_response_url = event.response.url
            captured_response_headers = dict(event.response.headers)
            captured_status_code = event.response.status
            logging.debug(f"[RESPONSE-HEADERS] Captured {len(captured_response_headers)} headers, status: {captured_status_code}")

    # navigate to the page
    logging.debug(f"[NAVIGATION] Starting navigation to: {req.url}")
    logging.debug(f"[NAVIGATION] Method: {method}")

    # Always open blank page first to enable network monitoring
    # Add timeout to prevent hanging on stuck sessions
    try:
        tab = await asyncio.wait_for(
            driver.get("about:blank"),
            timeout=15.0
        )
    except asyncio.TimeoutError:
        logging.warning("[NAVIGATION] Timeout opening blank page, browser may be stuck")
        raise Exception("Browser session is stuck. Try destroying and recreating the session.")

    # Enable network monitoring with error handling
    try:
        await tab.send(utils.nd.cdp.network.enable())
        network_enabled = True
        logging.debug("[NETWORK] Network monitoring enabled")

        # Add handler to capture response headers
        tab.add_handler(utils.nd.cdp.network.ResponseReceived, on_response_received)
        logging.debug("[NETWORK] Response handler added")
    except Exception as e:
        logging.warning(f"[NETWORK] Failed to enable network monitoring: {e}")
        logging.warning("[NETWORK] Response headers will not be captured for this request")

    # Set custom headers if provided
    if req.headers is not None and len(req.headers) > 0:
        try:
            logging.debug(f"[HEADERS] Setting custom headers: {req.headers}")
            await tab.send(utils.nd.cdp.network.set_extra_http_headers(
                utils.nd.cdp.network.Headers(req.headers)
            ))
            logging.debug("[HEADERS] Custom headers set successfully")
        except Exception as e:
            logging.warning(f"[HEADERS] Failed to set custom headers: {e}")

    # Navigate to actual URL
    # For JSON POST (dict postData): navigate normally, fetch after challenge
    # For form POST (string postData): use data: URL with form submit
    is_json_post = method == "POST" and isinstance(req.postData, dict)

    if method == "POST" and not is_json_post:
        # Form-urlencoded POST: use existing data: URL approach
        post_content = await _post_request_nd(req)
        logging.debug(f"[NAVIGATION] POST content generated, length: {len(post_content)} chars")
        await tab.get("data:text/html;charset=utf-8," + post_content)
    else:
        # GET or JSON POST: navigate to URL directly with timeout
        try:
            await asyncio.wait_for(
                tab.get(req.url),
                timeout=30.0
            )
        except asyncio.TimeoutError:
            logging.warning(f"[NAVIGATION] Timeout navigating to {req.url}")
            raise Exception("Navigation timeout. The page took too long to respond.")

    logging.debug(f"[NAVIGATION] Navigation completed, tab target: {tab.target.target_id if tab.target else 'None'}")
    logging.debug(f"[NAVIGATION] Tab URL: {tab.target.url if tab.target else 'None'}")
    logging.debug(f"[NAVIGATION] Tab title: {tab.target.title if tab.target else 'None'}")

    # Insert cookies in Browser if set
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f"[COOKIES] Processing {len(req.cookies)} cookies from request")
        await tab.wait(1)
        await tab
        logging.debug(f"[COOKIES] Setting cookies...")

        # Get cleaned domain
        domain = (urlparse(req.url).netloc).split(".")
        domain = ".".join(domain[-2:])
        logging.debug(f"[COOKIES] Target domain: {domain}")

        # Delete all cookies
        logging.debug("[COOKIES] Removing all Browser cookies...")
        await driver.cookies.clear()

        cookies: List[utils.nd.cdp.network.CookieParam] = []
        for cookie in req.cookies:
            if domain not in cookie["domain"]:
                logging.debug(f"[COOKIES] Skipping cookie from domain {cookie['domain']}")
                continue
            logging.debug(
                f"[COOKIES] Appending cookie '{cookie['name']}' for '{cookie['domain']}'..."
            )
            cookies.append(
                utils.nd.cdp.network.CookieParam(
                    name=cookie["name"],
                    value=cookie["value"],
                    path=cookie["path"],
                    domain=cookie["domain"],
                )
            )

        await driver.cookies.set_all(cookies)
        logging.debug(f"[COOKIES] Set {len(cookies)} cookies successfully")

        # reload the page
        if method == "POST" and not is_json_post:
            tab = await driver.get(post_content)
        else:
            logging.debug("[NAVIGATION] Reloading tab after cookie injection...")
            await tab.reload()

    # wait for the page and make sure it catches the load event
    logging.debug("[PAGE] Waiting for page load event...")
    await tab.wait(1)
    await tab
    logging.debug("[PAGE] Page load event received")

    # get current page nodes
    logging.debug("[DOM] Requesting DOM document...")
    doc: utils.nd.cdp.dom.Node = await tab.send(utils.nd.cdp.dom.get_document(-1, True))
    logging.debug(f"[DOM] Document received: {doc is not None}")
    if doc:
        logging.debug(f"[DOM] Document node_id: {doc.node_id}, node_name: {doc.node_name}")

    if utils.get_config_log_html():
        logging.debug(f"Response HTML:\n{await tab.get_content(_node=doc)}")
    page_title = tab.target.title
    logging.debug(f"[PAGE] Page title: '{page_title}'")

    # find access denied titles
    logging.debug(f"[DETECTION] Checking for access denied titles...")
    for title in ACCESS_DENIED_TITLES:
        if title == page_title:
            logging.warning(f"[DETECTION] Access denied title matched: '{title}'")
            raise Exception(
                "Cloudflare has blocked this request. "
                "Probably your IP is banned for this site, check in your web browser."
            )
    # find access denied selectors
    logging.debug(f"[DETECTION] Checking for access denied selectors...")
    for selector in ACCESS_DENIED_SELECTORS:
        found_elements = await tab.query_selector(selector=selector, _node=doc)
        if found_elements is not None:
            logging.warning(f"[DETECTION] Access denied selector found: '{selector}'")
            raise Exception(
                "Cloudflare has blocked this request. "
                "Probably your IP is banned for this site, check in your web browser."
            )

    # find challenge by title
    logging.debug(f"[DETECTION] Checking for challenge titles...")
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info(f"[DETECTION] Challenge detected. Title found: '{page_title}'")
            break
    if not challenge_found:
        # find challenge by selectors
        logging.debug(f"[DETECTION] Checking for challenge selectors...")
        for selector in CHALLENGE_SELECTORS:
            found_elements = await tab.query_selector(selector=selector, _node=doc)
            if found_elements is not None:
                challenge_found = True
                logging.info(f"[DETECTION] Challenge detected. Selector found: '{selector}'")
                break

    if not challenge_found:
        logging.debug("[DETECTION] No challenge detected")

    attempt = 0
    if challenge_found:
        logging.debug("[CHALLENGE] Starting challenge resolution loop...")
        while True:
            try:
                attempt = attempt + 1
                logging.debug(f"[CHALLENGE] Attempt {attempt} - waiting for page...")
                await tab.wait(1)

                # wait until the title changes
                for title in CHALLENGE_TITLES:
                    logging.debug(
                        f"[CHALLENGE] Waiting for title change (attempt {attempt}): '{title}'"
                    )
                    if tab.target.title != title:
                        continue
                    start_time = time.time()
                    while True:
                        current_title = tab.target.title
                        if current_title not in CHALLENGE_TITLES:
                            logging.debug(f"[CHALLENGE] Title changed to: '{current_title}'")
                            break
                        if time.time() - start_time > SHORT_TIMEOUT:
                            logging.debug(f"[CHALLENGE] Timeout waiting for title change")
                            raise TimeoutError
                        await tab.wait(0.1)

                # then wait until all the selectors disappear
                for selector in CHALLENGE_SELECTORS:
                    await tab
                    logging.debug(
                        f"[CHALLENGE] Waiting for selector to disappear (attempt {attempt}): '{selector}'"
                    )
                    if (
                        await tab.query_selector(selector=selector, _node=doc)
                        is not None
                    ):
                        start_time = time.time()
                        while True:
                            element = await tab.query_selector(
                                selector=selector, _node=doc
                            )
                            if not element:
                                logging.debug(f"[CHALLENGE] Selector disappeared: '{selector}'")
                                break
                            if time.time() - start_time > SHORT_TIMEOUT:
                                logging.debug(f"[CHALLENGE] Timeout waiting for selector to disappear")
                                raise TimeoutError
                            del element
                            await asyncio.sleep(0.1)

                # all elements not found
                logging.debug("[CHALLENGE] All challenge elements cleared")
                break

            except TimeoutError:
                logging.debug(f"[CHALLENGE] Timeout on attempt {attempt}, trying to click verify...")
                await click_verify_nd(tab)

        # waits until cloudflare redirection ends
        logging.debug("[CHALLENGE] Waiting for final redirect...")
        # noinspection PyBroadException
        try:
            await tab
        except Exception:
            logging.debug("[CHALLENGE] Timeout waiting for redirect")

        logging.info("[CHALLENGE] Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("[CHALLENGE] Challenge not detected!")
        res.message = "Challenge not detected!"

    # For JSON POST: execute fetch after challenge is solved (same-origin request)
    if is_json_post:
        import json
        logging.info("[JSON POST] Executing fetch request after challenge resolution...")
        json_data = json.dumps(req.postData)
        # Escape for JavaScript string
        json_data_escaped = json_data.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n').replace('\r', '\\r')

        # Build headers object including custom headers from request
        fetch_headers = {'Content-Type': 'application/json'}
        if req.headers:
            fetch_headers.update(req.headers)

        # Convert headers to JavaScript object string
        headers_js = json.dumps(fetch_headers)
        logging.debug(f"[JSON POST] Fetch headers: {fetch_headers}")

        fetch_script = f"""
        (async () => {{
            try {{
                const response = await fetch('{req.url}', {{
                    method: 'POST',
                    headers: {headers_js},
                    body: '{json_data_escaped}'
                }});
                const text = await response.text();
                document.open();
                document.write(text);
                document.close();
                return 'success';
            }} catch (error) {{
                return 'error: ' + error.message;
            }}
        }})()
        """

        try:
            result = await tab.evaluate(fetch_script)
            logging.debug(f"[JSON POST] Fetch result: {result}")
            # Wait for DOM to update
            await tab.wait(1)
            # Refresh doc reference after DOM change
            doc = await tab.send(utils.nd.cdp.dom.get_document(-1, True))
            logging.info("[JSON POST] Fetch completed successfully")
        except Exception as e:
            logging.warning(f"[JSON POST] Fetch failed: {e}")

    logging.debug("[RESPONSE] Building response object...")

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = tab.target.url
    logging.debug(f"[RESPONSE] Final URL: {challenge_res.url}")

    challenge_res.status = captured_status_code
    logging.debug(f"[RESPONSE] Status code: {challenge_res.status}")

    logging.debug("[RESPONSE] Retrieving cookies...")
    try:
        challenge_res.cookies = await asyncio.wait_for(
            driver.cookies.get_all(requests_cookie_format=True),
            timeout=10.0
        )
        logging.debug(f"[RESPONSE] Retrieved {len(challenge_res.cookies)} cookies")
    except asyncio.TimeoutError:
        logging.warning("[RESPONSE] Cookie retrieval timed out, returning empty cookies")
        challenge_res.cookies = []

    logging.debug("[RESPONSE] Retrieving user agent...")
    challenge_res.userAgent = await utils.get_user_agent_nd(driver)
    logging.debug(f"[RESPONSE] User agent: {challenge_res.userAgent}")

    if not req.returnOnlyCookies:
        if network_enabled:
            challenge_res.headers = captured_response_headers
            logging.debug(f"[RESPONSE] Headers: {len(challenge_res.headers)} headers captured")
            if captured_response_url and captured_response_url != req.url:
                logging.debug(f"[RESPONSE] Note: Final URL differs from requested (redirect occurred)")
        else:
            challenge_res.headers = {}
            logging.debug("[RESPONSE] Headers: not captured (network monitoring unavailable)")

        logging.debug("[RESPONSE] Retrieving page content...")
        challenge_res.response = await tab.get_content(_node=doc)
        content_length = len(challenge_res.response) if challenge_res.response else 0
        logging.debug(f"[RESPONSE] Page content length: {content_length} chars")

        # Extract JSON from HTML wrapper if content-type is application/json
        content_type = challenge_res.headers.get('content-type', '')
        if 'application/json' in content_type and challenge_res.response:
            import re
            # Chrome wraps JSON in: <html>...<body><pre>JSON</pre>...</body></html>
            match = re.search(r'<pre[^>]*>(.*?)</pre>', challenge_res.response, re.DOTALL)
            if match:
                challenge_res.response = match.group(1)
                logging.debug("[RESPONSE] Extracted JSON from HTML wrapper")

        # Log first 500 chars of content for debugging
        if challenge_res.response and content_length > 0:
            preview = challenge_res.response[:500].replace('\n', ' ').replace('\r', '')
            logging.debug(f"[RESPONSE] Content preview: {preview}...")
        elif content_length == 0:
            logging.warning("[RESPONSE] Warning: Page content is empty!")

    # Remove network handler before closing to prevent memory leaks
    if network_enabled:
        try:
            tab.handlers.pop(utils.nd.cdp.network.ResponseReceived, None)
            logging.debug("[CLEANUP] Response handler removed")
        except Exception as e:
            logging.debug(f"[CLEANUP] Handler removal note: {e}")

    # Close websocket connection
    # to reuse the driver tab
    if req.session:
        logging.debug("[CLEANUP] Closing tab websocket (session mode)...")
        await tab.aclose()
    else:
        logging.debug("[CLEANUP] Closing tab...")
        await tab.close()
        logging.debug("[CLEANUP] Tab was closed")

    res.result = challenge_res
    logging.debug("[RESPONSE] Response object built successfully")
    return res


async def click_verify_nd(tab: Tab):
    try:
        logging.debug("Checking if cloudflare captcha is present on page...")
        await tab.wait(2)
        await tab
        cf_element = await tab.find(text="cf-chl-widget-", timeout=SHORT_TIMEOUT)

        if cf_element:
            logging.debug("Cloudflare captcha found!")

            # update targets before looking for the iframe
            # nodriver list it in LOG_LEVEL debug but not in info
            await tab.browser.update_targets()
            # get the iframe target
            cf_tab = next(
                (
                    target
                    for target in tab.browser.targets
                    if "challenges.cloudflare.com" in target.url
                ),
                None,
            )
            if cf_tab is None:
                raise ValueError("Captcha iframe not found!")

            # Fix iframe being denied access by websocket
            cf_tab.websocket_url = cf_tab.websocket_url.replace("iframe", "page")

            logging.debug("Found captcha iframe!")

            # get checkbox from iframe
            cf_checkbox = await cf_tab.find(text="checkbox", timeout=SHORT_TIMEOUT)

            await cf_checkbox.mouse_click()
            logging.debug("Checkbox element clicked!")
    except Exception as e:
        logging.debug(f"Cloudflare element not found on the page - {str(e)}")

    await asyncio.sleep(2)


async def _post_request_nd(req: V1RequestBase) -> str:
    import json

    # Check if postData is a dict (JSON) or string (form-urlencoded)
    if isinstance(req.postData, dict):
        # JSON POST using fetch API
        json_data = json.dumps(req.postData)
        # Escape for JavaScript string
        json_data_escaped = json_data.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n')

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"></head>
        <body>
            <div id="result">Sending JSON POST request...</div>
            <script>
                fetch('{req.url}', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: '{json_data_escaped}'
                }})
                .then(response => response.text())
                .then(data => {{
                    document.body.innerHTML = data;
                }})
                .catch(error => {{
                    document.getElementById('result').innerText = 'Error: ' + error;
                }});
            </script>
        </body>
        </html>"""
        logging.debug(f"[POST] Sending JSON request to {req.url}")
    else:
        # Form-urlencoded POST (original behavior)
        post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
        query_string = req.postData if req.postData[0] != "?" else req.postData[1:]
        pairs = query_string.split("&")
        for pair in pairs:
            parts = pair.split("=")
            # noinspection PyBroadException
            try:
                name = unquote(parts[0])
            except Exception:
                name = parts[0]
            if name == "submit":
                continue
            # noinspection PyBroadException
            try:
                value = unquote(parts[1])
            except Exception:
                value = parts[1]
            post_form += f'<input type="text" name="{name}" value="{value}"><br>'
        post_form += "</form>"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
        logging.debug(f"[POST] Sending form-urlencoded request to {req.url}")

    return html_content
