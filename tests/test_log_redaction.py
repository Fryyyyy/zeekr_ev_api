"""Credential values must not reach the log through the request layer.

The end-to-end tests are the point: they drive real request functions with
logging at DEBUG and assert the secrets are absent. The unit tests below only
explain why it holds. Two residues are known and out of scope here, documented
in redact.py: the TSP `data.code`, and credentials that `client` interpolates
into exception messages.
"""

import json
import logging
from unittest.mock import MagicMock

import pytest
import requests

from zeekr_ev_api import network
from zeekr_ev_api.network import _safe_json
from zeekr_ev_api.redact import (
    REDACTED,
    redact,
    redact_header_lines,
    redact_headers,
    safe_body,
)

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-session-token"
ACCESS_KEY = "AK-super-secret-access-key"
SECRET_KEY = "SK-super-secret-secret-key"


def _client() -> MagicMock:
    """A client whose session echoes a harmless JSON response."""
    client = MagicMock()
    client.logger = logging.getLogger("zeekr_ev_api.network")
    client.bearer_token = TOKEN
    client.logged_in_headers = {"authorization": TOKEN, "content-type": "application/json"}
    client.prod_secret = "prod-secret"
    client.hmac_access_key = ACCESS_KEY
    client.hmac_secret_key = SECRET_KEY
    client.timeout = (10, 30)

    resp = MagicMock()
    resp.json.return_value = {"code": 200, "data": {"accessToken": TOKEN}}
    resp.text = json.dumps({"code": 200, "data": {"accessToken": TOKEN}})
    resp.headers = {"content-type": "application/json", "set-cookie": f"session={TOKEN}"}
    resp.status_code = 200
    client.session.send.return_value = resp
    client.session.prepare_request.side_effect = lambda r: requests.Session().prepare_request(r)
    return client


# --- end-to-end: the property that actually matters -------------------------


@pytest.mark.parametrize("call", ["appSignedGet", "appSignedPost"])
def test_signed_requests_never_log_the_bearer_token(caplog, call):
    caplog.set_level(logging.DEBUG)
    getattr(network, call)(_client(), "https://example.invalid/api/v1/status")
    assert TOKEN not in caplog.text
    assert REDACTED in caplog.text


@pytest.mark.parametrize("call", ["customGet", "customPost"])
def test_hmac_requests_never_log_the_hmac_secrets(caplog, call):
    caplog.set_level(logging.DEBUG)
    getattr(network, call)(_client(), "https://example.invalid/api/v1/login")
    assert ACCESS_KEY not in caplog.text
    assert "X-HMAC-ACCESS-KEY" in caplog.text, "the header name should stay visible"
    assert REDACTED in caplog.text


def test_the_signature_base_string_does_not_leak_the_token(caplog):
    """The base string is built from the canonical headers, authorization included."""
    caplog.set_level(logging.DEBUG)
    network.appSignedGet(_client(), "https://example.invalid/api/v1/status")
    base_string_lines = [r.message for r in caplog.records if "authorization:" in r.message]
    assert base_string_lines, "expected the signature base string to be logged"
    assert all(TOKEN not in line for line in base_string_lines)


# --- unit level -------------------------------------------------------------


def test_redact_headers_masks_credentials_but_keeps_the_names():
    out = redact_headers({"Authorization": TOKEN, "content-type": "application/json"})
    assert out["Authorization"] == REDACTED
    assert out["content-type"] == "application/json"


def test_redact_headers_covers_the_hmac_headers():
    out = redact_headers({"X-HMAC-ACCESS-KEY": ACCESS_KEY, "X-HMAC-SIGNATURE": "sig"})
    assert set(out.values()) == {REDACTED}


def test_redact_headers_accepts_a_case_insensitive_dict():
    """Every real call site passes requests' CaseInsensitiveDict, not a plain dict."""
    headers = requests.structures.CaseInsensitiveDict({"authorization": TOKEN})
    assert redact_headers(headers)["authorization"] == REDACTED


def test_redact_masks_token_keys_in_any_spelling_and_depth():
    out = redact(
        {
            "code": 200,
            "data": {
                "accessToken": TOKEN,
                "refresh_token": "r",
                "tokenValue": TOKEN,
                "profile": {"name": "Pieter", "password": "hunter2"},
                "sessions": [{"idToken": TOKEN}],
            },
        }
    )
    assert out["code"] == 200
    assert out["data"]["profile"]["name"] == "Pieter"
    assert out["data"]["profile"]["password"] == REDACTED
    assert TOKEN not in json.dumps(out)
    assert out["data"]["tokenValue"] == REDACTED
    assert out["data"]["sessions"][0]["idToken"] == REDACTED


def test_redact_header_lines_masks_only_credential_lines():
    base = f"authorization:{TOKEN}\nx-timestamp:123\nGET\n/api/v1/status"
    out = redact_header_lines(base)
    assert TOKEN not in out
    assert "x-timestamp:123" in out
    assert "/api/v1/status" in out
    assert "GET" in out


def test_safe_body_masks_json_and_survives_everything_else():
    assert TOKEN not in safe_body(json.dumps({"data": {"accessToken": TOKEN}}))
    assert REDACTED in safe_body(json.dumps({"accessToken": TOKEN}))
    assert safe_body(None) == "(empty)"
    assert safe_body("") == "(empty)"
    # Non-JSON is kept readable on purpose; that excerpt is what makes a 502 diagnosable.
    html = "<html>gateway error</html>"
    assert safe_body(html) == html


def test_safe_body_actually_parses_bytes():
    rendered = safe_body(json.dumps({"accessToken": TOKEN}).encode())
    assert TOKEN not in rendered
    assert REDACTED in rendered, "bytes must be parsed and redacted, not fall through"


@pytest.mark.parametrize("body", [12345, iter([b"chunk"]), object()])
def test_safe_body_never_raises_on_an_unusual_body(body):
    """requests accepts ints, iterators and file objects as data=."""
    assert "unparsed body" in safe_body(body)


def test_safe_json_error_path_does_not_log_the_body_verbatim():
    resp = MagicMock()
    resp.json.side_effect = ValueError("Expecting value")
    resp.status_code = 502
    resp.text = f"<html>gateway error, trace-id=abc123, token={TOKEN}</html>"
    logger = MagicMock()

    result = _safe_json(resp, logger)

    assert result["success"] is False
    assert result["status_code"] == 502
    logged = " ".join(str(a) for call in logger.error.call_args_list for a in call.args)
    assert TOKEN not in logged
    assert "trace-id=abc123" in logged, "a 502 must stay diagnosable"


def test_safe_json_returns_parsed_json_untouched():
    resp = MagicMock()
    resp.json.return_value = {"data": {"accessToken": TOKEN}}
    # Redaction is for logging only — callers still need the real token.
    assert _safe_json(resp, MagicMock())["data"]["accessToken"] == TOKEN


def test_x_signature_header_is_masked():
    """X-SIGNATURE is added by sign_request and had no coverage."""
    assert redact_headers({"X-SIGNATURE": "sig-value"})["X-SIGNATURE"] == REDACTED


def test_safe_body_keeps_a_bounded_excerpt_of_non_json():
    html = "<html>upstream connect error: connection timeout; trace-id=abc123</html>"
    assert "trace-id=abc123" in safe_body(html)


def test_safe_body_scrubs_form_encoded_credentials():
    rendered = safe_body(f"user=pieter&access_token={TOKEN}&lang=nl")
    assert TOKEN not in rendered
    assert "user=pieter" in rendered
    assert "lang=nl" in rendered


def test_safe_body_masks_a_token_with_no_key_to_match_on():
    """A bare JSON scalar, or a token echoed inside an error page."""
    assert TOKEN not in safe_body(f'"{TOKEN}"')
    assert TOKEN not in safe_body(f"<html>session expired: {TOKEN}</html>")
    assert REDACTED in safe_body(f'"{TOKEN}"')


def test_safe_body_truncates_a_long_body():
    rendered = safe_body("x" * 2000)
    assert len(rendered) <= 520
    assert rendered.endswith("\u2026")
