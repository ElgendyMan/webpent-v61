"""Read-only HackerOne Hacker API adapter (v1).

Credentials are resolved only from environment-variable references.  There are no
write endpoints, report methods, browser cookies, or target-testing capabilities in
this adapter.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from ..errors import (
    ForbiddenError,
    NotFoundError,
    ProviderUnavailableError,
    RateLimitedError,
    SchemaChangedError,
    UnauthorizedError,
)
from ..models import ProgramSummary, ScopeAsset
from .base import CredentialRef, ProviderHealth


class HackerOneProvider:
    provider_name = "hackerone"
    adapter_version = "hackerone-v1-readonly"
    base_url = "https://api.hackerone.com/v1/hackers"

    def __init__(
        self, credential_ref: CredentialRef | None = None, *, timeout_seconds: int = 20
    ) -> None:
        self.credential_ref = credential_ref or CredentialRef(
            username_env="BBSCOUT_HACKERONE_TOKEN_ID",
            token_env="BBSCOUT_HACKERONE_TOKEN",
        )
        self.timeout_seconds = timeout_seconds
        self._last_request_at = 0.0

    def _credentials(self) -> tuple[str, str]:
        if not self.credential_ref.username_env or not self.credential_ref.token_env:
            raise UnauthorizedError("HackerOne credential reference غير مكتمل.")
        username = os.environ.get(self.credential_ref.username_env)
        token = os.environ.get(self.credential_ref.token_env)
        if not username or not token:
            raise UnauthorizedError(
                "بيانات HackerOne غير متاحة. عيّن "
                "BBSCOUT_HACKERONE_TOKEN_ID وBBSCOUT_HACKERONE_TOKEN في البيئة؛ "
                "لا تمررهم كـ CLI arguments."
            )
        return username, token

    def _wait_rate_limit(self, *, structured_scope: bool) -> None:
        # Lower than the documented limits: 1.25 sec for scopes (<50/min), and
        # 0.12 sec for normal reads (<600/min).
        minimum = 1.25 if structured_scope else 0.12
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < minimum:
            time.sleep(minimum - elapsed)

    @staticmethod
    def _safe_next_url(url: str) -> bool:
        parsed = urlparse(url)
        return (
            parsed.scheme == "https"
            and parsed.netloc == "api.hackerone.com"
            and parsed.path.startswith("/v1/hackers/")
        )

    def _request_json(self, path_or_url: str, *, structured_scope: bool = False) -> dict[str, Any]:
        url = path_or_url if path_or_url.startswith("https://") else f"{self.base_url}{path_or_url}"
        if not self._safe_next_url(url):
            raise SchemaChangedError(
                "Provider pagination أرجعت رابط خارج نطاق HackerOne API المسموح."
            )
        username, token = self._credentials()
        encoded = base64.b64encode(f"{username}:{token}".encode()).decode("ascii")
        self._wait_rate_limit(structured_scope=structured_scope)
        request = Request(
            url,
            headers={"Accept": "application/json", "Authorization": f"Basic {encoded}"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                self._last_request_at = time.monotonic()
                body = response.read().decode("utf-8")
                try:
                    result = json.loads(body)
                except json.JSONDecodeError as exc:
                    raise SchemaChangedError("HackerOne API أرجعت JSON غير صالح.") from exc
                if not isinstance(result, dict):
                    raise SchemaChangedError("HackerOne API أرجعت response غير متوقع.")
                return result
        except HTTPError as exc:
            request_id = exc.headers.get("X-Request-ID") if exc.headers else None
            if exc.code == 401:
                raise UnauthorizedError(
                    "HackerOne رفض بيانات المصادقة.", request_id=request_id
                ) from exc
            if exc.code == 403:
                raise ForbiddenError(
                    "HackerOne منع الوصول للـ resource؛ ليست قائمة فارغة.", request_id=request_id
                ) from exc
            if exc.code == 404:
                raise NotFoundError(
                    "HackerOne لم يجد الـ resource المطلوب.", request_id=request_id
                ) from exc
            if exc.code == 429:
                raise RateLimitedError(
                    "HackerOne rate limit تم تجاوزه؛ أعد المحاولة لاحقًا.", request_id=request_id
                ) from exc
            if exc.code >= 500:
                raise ProviderUnavailableError(
                    f"HackerOne غير متاح حاليًا (HTTP {exc.code}).", request_id=request_id
                ) from exc
            raise ProviderUnavailableError(
                f"HackerOne API أرجعت HTTP {exc.code}.", request_id=request_id
            ) from exc
        except URLError as exc:
            raise ProviderUnavailableError("تعذر الاتصال بـ HackerOne API.") from exc

    def _get_all(self, path: str, *, structured_scope: bool = False) -> list[dict[str, Any]]:
        next_url: str | None = path
        records: list[dict[str, Any]] = []
        pages = 0
        while next_url:
            pages += 1
            if pages > 1000:
                raise SchemaChangedError("تم إيقاف pagination بعد 1000 صفحة كحد أمان.")
            document = self._request_json(next_url, structured_scope=structured_scope)
            data = document.get("data")
            if not isinstance(data, list):
                raise SchemaChangedError("HackerOne response لا تحتوي data list متوقعة.")
            records.extend(item for item in data if isinstance(item, dict))
            candidate = (
                document.get("links", {}).get("next")
                if isinstance(document.get("links"), dict)
                else None
            )
            next_url = candidate if isinstance(candidate, str) and candidate else None
        return records

    @staticmethod
    def _program(record: dict[str, Any]) -> ProgramSummary:
        try:
            attributes = record["attributes"]
            handle = str(attributes["handle"])
            return ProgramSummary(
                provider="hackerone",
                program_id=str(record["id"]),
                handle=handle,
                name=str(attributes.get("name", handle)),
                status=str(attributes.get("submission_state", attributes.get("state", "unknown"))),
                visibility=str(attributes.get("state", "unknown")),
                updated_at=attributes.get("updated_at"),
                access_state="visible",
                tags=[],
                policy_text=attributes.get("policy"),
                source_url=f"https://hackerone.com/{handle}",
            )
        except (KeyError, TypeError) as exc:
            raise SchemaChangedError("HackerOne program schema تغيّر أو ينقصه handle/id.") from exc

    def health_check(self) -> ProviderHealth:
        self.list_accessible_programs()
        return ProviderHealth(
            self.provider_name,
            True,
            "authenticated read-only API access confirmed",
            self.adapter_version,
        )

    def list_accessible_programs(self) -> list[ProgramSummary]:
        return [self._program(record) for record in self._get_all("/programs")]

    def get_program(self, handle: str) -> ProgramSummary:
        safe_handle = quote(handle, safe="")
        document = self._request_json(f"/programs/{safe_handle}")
        data = document.get("data")
        if not isinstance(data, dict):
            raise SchemaChangedError("HackerOne program response لا تحتوي data object.")
        return self._program(data)

    def get_scope(self, handle: str) -> list[ScopeAsset]:
        safe_handle = quote(handle, safe="")
        records = self._get_all(f"/programs/{safe_handle}/structured_scopes", structured_scope=True)
        assets: list[ScopeAsset] = []
        for record in records:
            try:
                attributes = record["attributes"]
                assets.append(
                    ScopeAsset(
                        asset_id=str(record["id"]),
                        asset_type=str(attributes["asset_type"]),
                        value=str(attributes["asset_identifier"]),
                        included=True,
                        eligible_for_submission=attributes.get("eligible_for_submission"),
                        instruction=attributes.get("instruction"),
                        updated_at=attributes.get("updated_at"),
                        source_id=str(record["id"]),
                        source_url=f"https://hackerone.com/{handle}",
                    )
                )
            except (KeyError, TypeError) as exc:
                raise SchemaChangedError("HackerOne structured scope schema تغيّر.") from exc
        return assets

    def get_policy(self, handle: str) -> str | None:
        return self.get_program(handle).policy_text
