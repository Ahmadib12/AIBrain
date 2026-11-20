from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.errors import register_error_handlers


def test_unexpected_exception_text_is_not_logged_or_returned(caplog) -> None:
    secret = "EXCEPTION_SECRET_Q64"
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/failure")
    async def failure() -> None:
        raise RuntimeError(secret)

    with caplog.at_level("ERROR", logger="aibrain.errors"):
        response = TestClient(app, raise_server_exceptions=False).get("/failure")

    assert response.status_code == 500
    assert secret not in response.text
    assert secret not in caplog.text
    assert "RuntimeError" in caplog.text
