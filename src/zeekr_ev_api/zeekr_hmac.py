import base64
import datetime
import hashlib
import hmac
import logging

from .redact import redact_headers
from typing import Dict

from urllib.parse import urlparse

from requests import Request

log = logging.getLogger(__name__)

# EEEE, dd MMM yyyy HH:mm:ss 'GMT'
DATE_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"


def _get_gmt_date() -> str:
    """Generates the GMT date string for X-DATE and the signature string."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime(DATE_FORMAT)


def hmac_sha256_base64(data: str, key: str) -> str:
    """Calculates Base64(HMAC-SHA256(key, data))"""
    h = hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256)
    return base64.b64encode(h.digest()).decode("utf-8")


def get_canonical_path(path_segments: list[str]) -> str:
    """Combines path segments into a canonical path, returning '/' if empty."""
    if not path_segments:
        return "/"
    return "/" + "/".join(segment for segment in path_segments if segment)


def parse_query_params(query_string: str) -> Dict[str, str]:
    """Parses a query string (e.g., 'a=1&b=2') into a dictionary."""
    params: Dict[str, str] = {}
    if not query_string:
        return params

    pairs = query_string.split("&")
    for pair in pairs:
        parts = pair.split("=", 1)  # Split only on the first '='
        if len(parts) == 2:
            key, value = parts
            params[key] = value

    return params


def get_canonical_query_string(query_map: Dict[str, str]) -> str:
    """
    Sorts query parameters case-insensitively by key and formats them
    as 'key1=value1&key2=value2...'.
    """
    if not query_map:
        return ""

    # Custom comparator for case-insensitive sort
    # sorted() with a key allows for case-insensitive sorting
    sorted_keys = sorted(query_map.keys(), key=lambda k: k.lower())

    parts = []
    for key in sorted_keys:
        value = str(query_map.get(key, ""))
        parts.append(f"{key}={value}")

    return "&".join(parts)


def get_request_body_content(body: str | bytes | None) -> str:
    """Reads the request body content as a UTF-8 string."""
    if body is None:
        return ""

    if isinstance(body, bytes):
        return body.decode("utf-8", errors="ignore")
    elif isinstance(body, str):
        return body
    else:
        # Handle other types like files or MultipartBody (which the Java code skips)
        return ""


def generateHMAC(request: Request, access_key: str,
                 secret_key: str) -> Request:
    parsed_url = urlparse(request.url)
    gmt_date = _get_gmt_date()

    path_segments = (parsed_url.path.strip("/").split("/")
                     if parsed_url.path.strip("/") else [])
    canonical_path = get_canonical_path(path_segments)

    query_map = parse_query_params(parsed_url.query)
    canonical_query = get_canonical_query_string(query_map)

    sign_string_components = [
        request.method.upper(),  # HTTP Method
        canonical_path,  # Canonical Path
        canonical_query,  # Canonical Query Parameters
        access_key,  # Access Key
        gmt_date,  # GMT Date
    ]
    sign_string = "\n".join(sign_string_components)

    signature = hmac_sha256_base64(sign_string + "\n", secret_key)

    request_body_content = get_request_body_content(request.data)
    body_digest = hmac_sha256_base64(request_body_content, secret_key)

    request.headers["X-HMAC-ALGORITHM"] = "hmac-sha256"
    request.headers["X-HMAC-SIGNATURE"] = signature
    request.headers["X-HMAC-ACCESS-KEY"] = access_key
    request.headers["X-HMAC-DIGEST"] = body_digest
    request.headers["X-DATE"] = gmt_date

    if log.isEnabledFor(logging.DEBUG):
        log.debug(f"Request Headers: {redact_headers(request.headers)}")

    return request
