"""Keep credential values out of the log.

Every signed request carries the live bearer token in its ``authorization``
header, and the HMAC path carries the caller's access key and derived digest.
All of that used to be logged verbatim. These helpers mask the values while
keeping the surrounding structure — header names, JSON shape, sizes, a bounded
excerpt of unparseable bodies — so debug output stays useful.

Redaction is for logging only; nothing here runs on the request path.

Matching is by known credential name, so it is best-effort rather than a
guarantee. Two residues are known and deliberately not covered:

* the single-use TSP code, which the gateway returns as ``data.code`` and the
  login request sends as ``identifier``. ``identifier`` is masked; ``code`` is
  not, because masking that substring would also hide ``countryCode``,
  ``errorCode`` and every ``code: 200``.
* credentials interpolated into exception messages by ``client``, which reach
  the log at ERROR without any debug logging enabled. That belongs in its own
  change.

This module imports nothing from the rest of the package: ``network`` imports
the signing modules, so the helpers cannot be shared from there.
"""

import json
import re
from typing import Any

REDACTED = "<redacted>"

#: Longest excerpt of an unparseable body to log.
MAX_BODY_EXCERPT = 500

#: Substrings marking a header or JSON key as holding a credential. Matched
#: against the name lowercased with "_" and "-" removed, so accessToken,
#: access_token and X-ACCESS-TOKEN all match. Substrings rather than exact
#: names because the shapes this gateway returns are not fully mapped, and
#: masking a harmless field costs less than leaking a token. That does mean
#: x-api-signature-nonce is masked too; that is fine.
SENSITIVE_NAME_PARTS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "credential",
    "apikey",
    "accesskey",
    "signature",
    "hmac",
    "sessionid",
    "identifier",
    "ticket",
)

_SCRUB = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:" + "|".join(SENSITIVE_NAME_PARTS) + r")[a-z0-9_-]*)"
    r"(\"?\s*[:=]\s*\"?)([^\"&;,\s]+)"
)


#: A JWT anywhere in free text, which is how this gateway's bearer tokens look.
#: Catches a token that arrives without a key name to match on.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]+)?")


def _is_sensitive_name(name: Any) -> bool:
    """Return True if a header or JSON key looks like it holds a credential."""
    if not isinstance(name, str):
        return False
    normalised = name.lower().replace("_", "").replace("-", "")
    return any(part in normalised for part in SENSITIVE_NAME_PARTS)


def redact_headers(headers) -> dict:
    """Copy headers for logging, masking credential values but keeping names."""
    try:
        items = headers.items()
    except AttributeError:
        return {}
    return {k: (REDACTED if _is_sensitive_name(k) else v) for k, v in items}


def redact(value: Any) -> Any:
    """Recursively mask credential values in a decoded JSON structure."""
    if isinstance(value, dict):
        return {k: (REDACTED if _is_sensitive_name(k) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def redact_header_lines(text: str) -> str:
    """Mask values in a "name:value\\n" block, such as a signature base string.

    Only lines whose prefix is a credential-looking header name are touched, so
    the query string, body hash, method and path in the same blob are left
    alone.
    """
    if not isinstance(text, str):
        return text
    lines = []
    for line in text.split("\n"):
        name, sep, _value = line.partition(":")
        if sep and _is_sensitive_name(name.strip()):
            lines.append(f"{name}{sep}{REDACTED}")
        else:
            lines.append(line)
    return "\n".join(lines)


def scrub_text(text: str) -> str:
    """Mask name=value and name:value pairs in text that is not JSON.

    Covers form-encoded bodies and gateway error pages that echo a parameter
    back. Anything it does not recognise is left readable on purpose — the
    excerpt is what makes a 502 diagnosable.
    """
    if not isinstance(text, str):
        return text
    text = _SCRUB.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return _JWT.sub(REDACTED, text)


def safe_body(body) -> str:
    """Render a request or response body for logging, with credentials masked.

    JSON objects and arrays are re-serialised with credential values replaced.
    Anything else — an HTML error page, a form-encoded body, a bare string — is
    scrubbed for name/value pairs and truncated, so a failing gateway is still
    diagnosable without risking a token.
    """
    if not body:
        return "(empty)"
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError, UnicodeDecodeError):
        parsed = None
    # A bare JSON scalar carries no key to match on, so treat it as text.
    if isinstance(parsed, (dict, list)):
        return json.dumps(redact(parsed))

    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", "replace")
        except (UnicodeDecodeError, AttributeError):  # pragma: no cover - defensive
            pass
    if not isinstance(body, str):
        if hasattr(body, "__len__"):
            return f"(unparsed body, {len(body)} bytes)"
        return f"(unparsed body, {type(body).__name__})"

    excerpt = scrub_text(body[:MAX_BODY_EXCERPT])
    suffix = "…" if len(body) > MAX_BODY_EXCERPT else ""
    return f"{excerpt}{suffix}"
