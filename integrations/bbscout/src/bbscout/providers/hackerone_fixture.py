"""Offline HackerOne adapter backed by deterministic fixtures.

It mirrors documented HackerOne read responses but intentionally performs no network
I/O. The live adapter is separate so tests cannot accidentally contact a provider.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..errors import NotFoundError, SchemaChangedError
from ..integrity import read_json
from ..models import ProgramSummary, ScopeAsset
from .base import ProviderHealth


class HackerOneFixtureProvider:
    provider_name = "hackerone"
    adapter_version = "hackerone-fixture-v1"

    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture_dir = Path(fixture_dir)
        self._programs_doc = read_json(self.fixture_dir / "programs.json")
        self._scopes_doc = read_json(self.fixture_dir / "scopes.json")
        if not isinstance(self._programs_doc.get("data"), list):
            raise SchemaChangedError("HackerOne fixture programs لا تحتوي data list.")

    def health_check(self) -> ProviderHealth:
        return ProviderHealth(
            provider=self.provider_name,
            healthy=True,
            detail="offline fixture mode; no provider network access",
            adapter_version=self.adapter_version,
        )

    @staticmethod
    def _to_program(record: dict[str, Any]) -> ProgramSummary:
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
                tags=[
                    value
                    for value in (
                        "api" if "api" in handle else "",
                        "browser" if attributes.get("open_scope") else "",
                    )
                    if value
                ],
                policy_text=attributes.get("policy"),
                source_url=f"https://hackerone.com/{handle}",
            )
        except (KeyError, TypeError) as exc:
            raise SchemaChangedError("HackerOne program fixture لا يطابق العقد المتوقع.") from exc

    def list_accessible_programs(self) -> list[ProgramSummary]:
        return [self._to_program(item) for item in self._programs_doc["data"]]

    def get_program(self, handle: str) -> ProgramSummary:
        for program in self.list_accessible_programs():
            if program.handle == handle:
                return program
        raise NotFoundError(f"برنامج HackerOne غير موجود في fixtures: {handle}")

    def get_scope(self, handle: str) -> list[ScopeAsset]:
        document = self._scopes_doc.get(handle)
        if not document or not isinstance(document.get("data"), list):
            raise NotFoundError(f"Structured scope غير موجودة في fixtures: {handle}")
        assets: list[ScopeAsset] = []
        for record in document["data"]:
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
                raise SchemaChangedError("HackerOne scope fixture لا يطابق العقد المتوقع.") from exc
        return assets

    def get_policy(self, handle: str) -> str | None:
        return self.get_program(handle).policy_text

    def raw_bundle(self, handle: str) -> dict[str, Any]:
        program = next(
            (
                item
                for item in self._programs_doc["data"]
                if item.get("attributes", {}).get("handle") == handle
            ),
            None,
        )
        scopes = self._scopes_doc.get(handle)
        if not program or not scopes:
            raise NotFoundError(f"Fixture bundle غير موجود: {handle}")
        return {
            "adapter_version": self.adapter_version,
            "program": program,
            "structured_scopes": scopes,
        }
