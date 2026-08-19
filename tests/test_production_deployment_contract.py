import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSE = PROJECT_ROOT / "docker-compose.yml"
DOCKERFILE = PROJECT_ROOT / "Dockerfile"
ENTRYPOINT = PROJECT_ROOT / "entrypoint.sh"


def test_production_compose_uses_container_bind_and_external_tls_redis() -> None:
    content = PRODUCTION_COMPOSE.read_text(encoding="utf-8")

    assert "WEBPENT_API_HOST=0.0.0.0" in content
    assert "WEBPENT_REDIS_URL=${REDIS_URL:?REDIS_URL must be set to a rediss:// URL}" in content
    assert (
        "WEBPENT_RATE_LIMIT_REDIS_URL=${RATE_LIMIT_REDIS_URL:?"
        "RATE_LIMIT_REDIS_URL must be set to a rediss:// URL}"
    ) in content
    assert "WEBPENT_AUTH_ENABLED=true" in content
    assert "WEBPENT_RATE_LIMIT_ENABLED=true" in content
    assert "redis://redis:6379" not in content


def test_production_compose_does_not_start_a_plaintext_redis_service() -> None:
    content = PRODUCTION_COMPOSE.read_text(encoding="utf-8")

    assert "\n  redis:\n" not in content
    assert "docker-compose.dev.yml" in content
    assert "externally managed Redis over TLS" in content


def test_entrypoint_drops_privileges_and_limits_ownership_reconciliation() -> None:
    content = ENTRYPOINT.read_text(encoding="utf-8")

    assert 'TARGET_USER="${WEBPENT_RUN_AS_USER:-webpent}"' in content
    assert 'exec gosu "${TARGET_UID}:${TARGET_GID}" "$@"' in content
    assert '"/app/webpent.db"' in content
    assert '"/app/memory"' in content
    assert '"/app/output"' in content
    assert "chmod -R 777" not in content


def test_ci_security_environment_contract_is_explicit() -> None:
    content = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for key, value in {
        "LLM_ENABLED": '"false"',
        "EMBEDDINGS_OFFLINE": '"true"',
        "DISABLE_RAG": '"true"',
        "AUTH_ENABLED": '"false"',
        "FFUF_ENABLED": '"false"',
        "WEBHOOK_ENABLED": '"false"',
    }.items():
        assert f"{key}: {value}" in content
    assert "verify_test_count.py --minimum 498" in content
    assert "tests/test_vip_audit_gap_closure.py" in content


def test_docker_image_metadata_matches_current_project_version() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert 'org.opencontainers.image.title="WebPent v60"' in content
    assert "ARG WEBPENT_VERSION=0.3.0" in content
    assert 'org.opencontainers.image.version="${WEBPENT_VERSION}"' in content
    assert 'ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]' in content
    assert not re.search(r"^USER\s+(?:root|webpent)\s*$", content, re.MULTILINE)
