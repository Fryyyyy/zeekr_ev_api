from zeekr_ev_api.client import ZeekrClient
from zeekr_ev_api import const
import pytest

def test_verify_fix():
    # 1. Setup
    # Ensure global state is clean initially
    const.LOGGED_IN_HEADERS["authorization"] = ""
    initial_global_auth = const.LOGGED_IN_HEADERS["authorization"]

    # 2. Initialize two clients
    client_a = ZeekrClient(username="user_a", password="password_a")
    client_b = ZeekrClient(username="user_b", password="password_b")

    # 3. Modify Client A's session
    token_a = "Bearer TOKEN_A"
    client_a.load_session({
        "username": "user_a",
        "bearer_token": token_a
    })

    # 4. Assert Global State is NOT Mutated
    assert const.LOGGED_IN_HEADERS["authorization"] == initial_global_auth, \
        f"Global headers should NOT be mutated. Expected '{initial_global_auth}', got '{const.LOGGED_IN_HEADERS['authorization']}'"

    # 5. Assert Client A has its own token
    assert client_a.logged_in_headers["authorization"] == token_a

    # 6. Client B load_session with different token
    token_b = "Bearer TOKEN_B"
    client_b.load_session({
        "username": "user_b",
        "bearer_token": token_b
    })

    # 7. Assert Client B has its own token
    assert client_b.logged_in_headers["authorization"] == token_b

    # 8. Assert Client A still has its original token
    assert client_a.logged_in_headers["authorization"] == token_a, \
        f"Client A headers should be independent. Expected '{token_a}', got '{client_a.logged_in_headers['authorization']}'"
