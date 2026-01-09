import logging
from typing import Any, TYPE_CHECKING
import json

from requests import Request
from . import const, zeekr_app_sig, zeekr_hmac

if TYPE_CHECKING:
    from .client import ZeekrClient

log = logging.getLogger(__name__)


def _safe_json(resp, logger) -> Any:
    """Safely parse JSON response, logging errors."""
    try:
        return resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        logger.error("Failed to decode JSON response: %s", e)
        logger.error("Response status: %s, text: %s", resp.status_code, resp.text[:500] if resp.text else "(empty)")
        return {"success": False, "error": f"Invalid JSON response: {e}", "status_code": resp.status_code}


def customPost(client: "ZeekrClient", url: str, body: dict | None = None) -> Any:
    """Sends a signed POST request with HMAC authentication."""
    logger = getattr(client, "logger", log)
    req = Request("POST", url, headers=const.DEFAULT_HEADERS, json=body)
    req = zeekr_hmac.generateHMAC(req, client.hmac_access_key, client.hmac_secret_key)

    prepped = client.session.prepare_request(req)
    resp = client.session.send(prepped)
    logger.debug("------ HEADERS ------")
    logger.debug(resp.headers)
    logger.debug("------ RESPONSE ------")
    logger.debug(resp.text)

    return _safe_json(resp, logger)


def customGet(client: "ZeekrClient", url: str) -> Any:
    """Sends a signed GET request with HMAC authentication."""
    logger = getattr(client, "logger", log)
    req = Request("GET", url, headers=const.DEFAULT_HEADERS)
    req = zeekr_hmac.generateHMAC(req, client.hmac_access_key, client.hmac_secret_key)

    prepped = client.session.prepare_request(req)
    resp = client.session.send(prepped)
    logger.debug("------ HEADERS ------")
    logger.debug(resp.headers)
    logger.debug("------ RESPONSE ------")
    logger.debug(resp.text)

    return _safe_json(resp, logger)


def appSignedPost(
    client: "ZeekrClient",
    url: str,
    body: str | None = None,
    extra_headers: dict | None = None,
) -> Any:
    """Sends a signed POST request with an app signature."""
    logger = getattr(client, "logger", log)
    req = Request("POST", url, headers=const.LOGGED_IN_HEADERS, data=body)
    if extra_headers:
        req.headers.update(extra_headers)
    prepped = client.session.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, client.prod_secret)

    logger.debug("--- Signed Request Details ---")
    logger.debug(f"Method: {final.method}")
    logger.debug(f"URL: {final.url}")
    logger.debug("Headers:")
    for k, v in final.headers.items():
        logger.debug(f"  {k}: {v}")
    logger.debug(f"Body: {final.body or ''}")
    logger.debug(f"\nX-SIGNATURE: {final.headers['X-SIGNATURE']}")

    resp = client.session.send(final)
    logger.debug("------ HEADERS ------")
    logger.debug(resp.headers)
    logger.debug("------ RESPONSE ------")
    logger.debug(resp.text)

    return _safe_json(resp, logger)


def appSignedGet(client: "ZeekrClient", url: str, headers: dict | None = None) -> Any:
    """Sends a signed GET request with an app signature."""
    if not client.bearer_token:
        raise Exception("Client is not logged in.")
    if not const.LOGGED_IN_HEADERS["authorization"]:
        const.LOGGED_IN_HEADERS["authorization"] = client.bearer_token
    logger = getattr(client, "logger", log)
    req = Request("GET", url, headers=const.LOGGED_IN_HEADERS)
    if headers:
        req.headers.update(headers)
    prepped = client.session.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, client.prod_secret)
    resp = client.session.send(final)
    logger.debug("------ HEADERS ------")
    logger.debug(resp.headers)
    logger.debug("------ RESPONSE ------")
    logger.debug(resp.text)

    return _safe_json(resp, logger)
