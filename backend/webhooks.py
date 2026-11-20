import json
import os
import re
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


WEBHOOK_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
URL_CHARACTERS = re.compile(r"[\x21-\x7e]+")


class WebhookError(Exception):
    def __init__(self, code: str, message: str, status_code: int | None = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def configured_webhooks() -> dict[str, str]:
    try:
        targets = json.loads(os.getenv("CYBER_GARDEN_WEBHOOKS", "{}"))
        if not isinstance(targets, dict):
            raise ValueError
        for ref, url in targets.items():
            if not WEBHOOK_REF.fullmatch(ref) or not isinstance(url, str) or not URL_CHARACTERS.fullmatch(url):
                raise ValueError
            address = urlsplit(url)
            if (
                address.scheme not in ("http", "https") or not address.hostname
                or address.username is not None or address.password is not None or address.fragment
                or address.port == 0
            ):
                raise ValueError
        return targets
    except ValueError:
        raise WebhookError(
            "invalid_webhook_settings", "Set CYBER_GARDEN_WEBHOOKS to a JSON object of names and HTTP(S) URLs."
        ) from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_webhook(ref: str, payload: dict) -> int:
    url = configured_webhooks().get(ref)
    if url is None:
        raise WebhookError("webhook_not_configured", "The selected webhook is not configured on the server.")

    request = Request(
        url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "CodeBloodhound"}, method="POST",
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=5) as response:
            status = response.status
            if 200 <= status < 300:
                return status
    except HTTPError as error:
        status = error.code
        error.close()
    except (OSError, HTTPException) as error:
        reason = error.reason if isinstance(error, URLError) else error
        if isinstance(reason, TimeoutError):
            raise WebhookError("webhook_timeout", "The webhook did not respond in time.") from None
        raise WebhookError("webhook_connection_error", "Could not connect to the webhook.") from None
    raise WebhookError("webhook_rejected", f"The webhook returned HTTP {status}.", status)
