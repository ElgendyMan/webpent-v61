import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dev_compose_binds_both_services_to_host_identity():
    compose = (ROOT / "docker-compose.dev.yml").read_text(encoding="utf-8")
    assert compose.count("WEBPENT_RUN_AS_UID=${WEBPENT_RUN_AS_UID:-1000}") == 2
    assert compose.count("WEBPENT_RUN_AS_GID=${WEBPENT_RUN_AS_GID:-1000}") == 2
    assert compose.count("./src:/app/src") == 2


def test_entrypoint_validates_numeric_identity_and_refuses_root_by_default():
    entrypoint = (ROOT / "entrypoint.sh").read_text(encoding="utf-8")
    assert 'TARGET_UID="${WEBPENT_RUN_AS_UID:-}"' in entrypoint
    assert 'TARGET_GID="${WEBPENT_RUN_AS_GID:-}"' in entrypoint
    assert 'WEBPENT_RUN_AS_UID/GID must be numeric and supplied together' in entrypoint
    assert 'TARGET_UID}" = "0"' in entrypoint
    assert 'WEBPENT_ALLOW_ROOT:-false' in entrypoint
    assert 'exec gosu "${TARGET_UID}:${TARGET_GID}" "$@"' in entrypoint


def test_worker_services_are_scalable_without_fixed_container_names():
    dev_compose = (ROOT / "docker-compose.dev.yml").read_text(encoding="utf-8")
    prod_compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for compose in (dev_compose, prod_compose):
        match = re.search(r"(?ms)^  worker:\n(.*?)(?=^  (?:[A-Za-z0-9_-]+:|#)|\\Z)", compose)
        assert match is not None
        worker_block = match.group(1)
        assert "container_name:" not in worker_block
        assert "celery -A worker.celery_app worker" in worker_block
