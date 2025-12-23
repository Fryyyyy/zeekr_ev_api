import logging
from typing import Any, TYPE_CHECKING

from requests import Request, Session
from . import const, zeekr_app_sig, zeekr_hmac

if TYPE_CHECKING:
    from .client import ZeekrClient

log = logging.getLogger(__name__)


def customPost(client: "ZeekrClient", url: str, body: dict | None = None) -> Any:
    """Sends a signed POST request with HMAC authentication."""
    req = Request("POST", url, headers=const.DEFAULT_HEADERS, json=body)
    req = zeekr_hmac.generateHMAC(req, client.hmac_access_key, client.hmac_secret_key)

    prepped = client.session.prepare_request(req)
    resp = client.session.send(prepped)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()


def customGet(client: "ZeekrClient", url: str) -> Any:
    """Sends a signed GET request with HMAC authentication."""
    req = Request("GET", url, headers=const.DEFAULT_HEADERS)
    req = zeekr_hmac.generateHMAC(req, client.hmac_access_key, client.hmac_secret_key)

    prepped = client.session.prepare_request(req)
    resp = client.session.send(prepped)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()


def appSignedPost(client: "ZeekrClient", url: str, body: str | None = None) -> Any:
    """Sends a signed POST request with an app signature."""
    req = Request("POST", url, headers=const.LOGGED_IN_HEADERS, data=body)
    prepped = client.session.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, client.prod_secret)

    log.debug("--- Signed Request Details ---")
    log.debug(f"Method: {final.method}")
    log.debug(f"URL: {final.url}")
    log.debug("Headers:")
    for k, v in final.headers.items():
        log.debug(f"  {k}: {v}")
    log.debug(f"Body: {final.body or ''}")
    log.debug(f"\nX-SIGNATURE: {final.headers['X-SIGNATURE']}")

    resp = client.session.send(final)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()


def appSignedGet(client: "ZeekrClient", url: str, headers: dict | None = None) -> Any:
    """Sends a signed GET request with an app signature."""
    req = Request("GET", url, headers=const.LOGGED_IN_HEADERS)
    if headers:
        req.headers.update(headers)
    prepped = client.session.prepare_request(req)

    final = zeekr_app_sig.sign_request(prepped, client.prod_secret)
    resp = client.session.send(final)
    log.debug("------ HEADERS ------")
    log.debug(resp.headers)
    log.debug("------ RESPONSE ------")
    log.debug(resp.text)

    return resp.json()
