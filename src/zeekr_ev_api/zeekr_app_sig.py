import base64
import hashlib
import hmac
import json
import logging

from .redact import redact_header_lines, redact_headers
import time
import uuid

from typing import List

from urllib.parse import urlparse, parse_qs

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from requests import PreparedRequest  # For type hinting and structure

log = logging.getLogger(__name__)

ALLOWED_HEADERS: list[str] = [
    "x-app-id",
    "content-type",
    "x-api-signature-nonce",
    "x-timestamp",
    "x-api-signature-version",
    "x-project-id",
    "authorization",
    "accept-language",
    "x-vin",
    "x-device-id",
    "x-platform",
]

# Keys with special validation requirements
X_VIN_HEADER: str = "x-vin"  # Must have a non-empty value
AUTH_HEADER: str = "authorization"  # Must have a non-empty value


def aes_encrypt(plain_text: str, key_hex: str, iv_hex: str) -> str:
    """
    Encrypts a string using AES/CBC/PKCS5Padding
    and returns a Base64 encoded string.

    Args:
        plain_text: The string to be encrypted.
        key_hex: The 16-byte key as a hexadecimal string.
        iv_hex: The 16-byte IV as a hexadecimal string.

    Returns:
        The Base64 encoded ciphertext string.
    """
    # Convert PlainText to bytes (Java uses StandardCharsets.UTF_8)
    plain_text_bytes = plain_text.encode("utf-8")

    # Create the AES cipher object in CBC mode
    # IV is passed as the `iv` parameter.
    cipher = AES.new(key_hex.encode("utf-8"), AES.MODE_CBC, iv=iv_hex.encode("utf-8"))

    # Apply PKCS7 Padding (PyCryptodome's `pad` function defaults to PKCS7,
    # which is equivalent to PKCS5 for AES's 16-byte block size).
    # block_size is 16 bytes (128 bits) for AES.
    padded_data = pad(plain_text_bytes, AES.block_size)

    # Encrypt the padded data
    ciphertext_bytes = cipher.encrypt(padded_data)

    # Encode the resulting bytes to Base64 (equivalent to Java's th.b.e())
    return base64.b64encode(ciphertext_bytes).decode("utf-8")


def validate_header(key: str, value: str) -> bool:
    """
    Validates if a given header should be included in the signature calculation.

    Args:
        key: The header key.
        value: The header value.

    Returns:
        True if the header is valid, False otherwise.
    """
    lower_key = key.lower()

    # 1. Check if key is allowed
    if lower_key not in ALLOWED_HEADERS:
        return False

    # 2. Check x-vin (must be non-empty)
    if lower_key == X_VIN_HEADER:
        return bool(value)  # returns true if value is not empty

    # 3. Check authorization (must be non-empty)
    return (lower_key != AUTH_HEADER) or bool(value)


def map_entry_to_dict_string(key: str, value: str, sb_list: list[str]) -> None:
    """Builds the Header part of the signature string."""
    lower_key = key.lower()
    sb_list.append(f"{lower_key}:{value}\n")


def map_entry_to_query_string(key: str, value: str, sb_list: list[str]) -> None:
    """Builds the Query part of the signature string."""
    encoded_value = value.replace("%2F", "/").replace("%3F", "?").replace("*", "%2A")

    if sb_list:
        sb_list.append("&")
    sb_list.append(f"{key}={encoded_value}")


# --- Core Logic ---
def calculate_sig(request: PreparedRequest, secret: str) -> str:
    """Calculates the signature for the given request using the provided secret."""
    # 1. Get request components
    method = request.method
    url_obj = urlparse(request.url)
    headers = request.headers

    # 2. Build the Canonical Headers String
    # The headers must be filtered, sorted by key, and formatted as 'key:value\n'
    canonical_headers: List[str] = []
    if headers:
        # Filter and sort headers
        filtered_headers = sorted(
            [(k.lower(), v) for k, v in headers.items() if validate_header(k, v)],
            key=lambda item: item[0],
        )

        for key, value in filtered_headers:
            map_entry_to_dict_string(key, value, canonical_headers)

    header_string = "".join(canonical_headers)

    # 3. Build the Canonical Query String
    # Query parameters are extracted, sorted by key, and formatted as 'key=value&...'
    canonical_query: list[str] = []
    if url_obj.query:
        # parse_qs returns a dict of lists; we need to flatten it, assume single values
        query_params = parse_qs(url_obj.query, keep_blank_values=True)

        # Sort keys and then flatten (assuming no multi-value parameters for simplicity)
        sorted_query_params = sorted(query_params.items())

        for key, values in sorted_query_params:
            # Assuming single value per key for simplicity
            value = values[0] if values else ""
            map_entry_to_query_string(key, value, canonical_query)

    query_string = "".join(canonical_query)

    # 4. Process Body (MD5 Hash for JSON body)
    body_hash_b64 = ""
    # The Java code checks for content-type: application/json
    if "application/json" in headers.get("Content-Type", "").lower():
        # Note: In OkHttp, RequestBody is a stream. In requests, it's usually bytes or a string.
        # We assume the request has a JSON body string/bytes.
        request_body = request.body

        if request_body:
            try:
                # Parse and canonicalize JSON (Java uses Gson().toJson(JsonObject))
                # Python equivalent: normalize the JSON structure (e.g., sort keys)
                if isinstance(request_body, (str, bytes)):
                    body_data = json.loads(request_body)
                    # Canonicalize by dumping with sorted keys and no separators/indent
                    canonical_json = json.dumps(
                        body_data, sort_keys=True, separators=(",", ":")
                    )
                else:
                    # Fallback for unexpected body type
                    canonical_json = str(request_body)

                # Calculate MD5 hash
                md5_hash = hashlib.md5(canonical_json.encode("utf-8")).digest()
                body_hash_b64 = base64.b64encode(md5_hash).decode("utf-8")
            except Exception:
                # Catch exceptions during body processing (e.g., non-JSON body despite header)
                pass

    # 5. Build the Signature Base String
    sig_base_list = []

    # Append canonical headers string
    if header_string:
        sig_base_list.append(header_string)

    # Append canonical query string + newline
    if query_string:
        sig_base_list.append(query_string)
        sig_base_list.append("\n")

    # Append MD5 body hash + newline
    if body_hash_b64:
        sig_base_list.append(body_hash_b64)
        sig_base_list.append("\n")

    # Append HTTP Method + newline
    assert method is not None
    sig_base_list.append(method.upper())
    sig_base_list.append("\n")

    sig_base_list.append(url_obj.path.rstrip())

    signature_base_string = "".join(sig_base_list)

    if log.isEnabledFor(logging.DEBUG):
        log.debug("--- DEBUG: SIGNATURE BASE STRING ---")
        log.debug(redact_header_lines(signature_base_string))
        log.debug("-----------------------------------")

    # 6. Calculate HMAC-SHA256
    h = hmac.new(
        secret.encode("utf-8"),
        signature_base_string.encode("utf-8"),
        hashlib.sha256,
    )

    hmac_digest = h.digest()

    # 7. Base64 Encode the HMAC digest
    signature = base64.b64encode(hmac_digest).decode("utf-8")

    return signature


# --- Intercept Logic (Python Integration) ---
def sign_request(request: PreparedRequest, secret: str) -> PreparedRequest:
    """
    Adds the calculated signature to the request headers.
    """
    # Remove existing signature (though not strictly necessary in requests)
    # Note: requests.Request/PreparedRequest headers are case-insensitive dicts
    if "X-SIGNATURE" in request.headers:
        del request.headers["X-SIGNATURE"]

    if (
        "x-api-signature-nonce" not in request.headers
        or "X-API-SIGNATURE-NONCE" not in request.headers
    ):
        request.headers["X-API-SIGNATURE-NONCE"] = str(uuid.uuid4())
    if "X-TIMESTAMP" not in request.headers or "x-timestamp" not in request.headers:
        request.headers["X-TIMESTAMP"] = str(time.time_ns() // 1000000)

    # Calculate and add new signature
    signature = calculate_sig(request, secret)
    request.headers["X-SIGNATURE"] = signature

    if log.isEnabledFor(logging.DEBUG):
        log.debug(f"Request Headers: {redact_headers(request.headers)}")

    return request
