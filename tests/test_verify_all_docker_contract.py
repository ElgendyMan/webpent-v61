import ast
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERIFY_ALL = PROJECT_ROOT / "verify_all.py"


def _load_base_image_checker():
    tree = ast.parse(VERIFY_ALL.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "dockerfile_uses_approved_base_image"
    )
    namespace = {"re": re}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(VERIFY_ALL), "exec"), namespace)
    return namespace[function.name]


def test_u1d_accepts_current_arg_based_dockerfile() -> None:
    checker = _load_base_image_checker()
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert checker(dockerfile) is True


def test_u1d_accepts_direct_approved_base_image() -> None:
    checker = _load_base_image_checker()

    assert checker("FROM webpent-base:latest\n") is True
    assert checker("ARG BASE_IMAGE=webpent-base:latest\nFROM $BASE_IMAGE AS app\n") is True
    assert checker(
        "ARG BASE_IMAGE = webpent-base:latest\n"
        "FROM --platform=$BUILDPLATFORM ${BASE_IMAGE} AS app\n"
    ) is True


def test_u1d_rejects_unapproved_or_unwired_base_image() -> None:
    checker = _load_base_image_checker()

    assert checker("FROM ubuntu:24.04\n") is False
    assert checker("ARG BASE_IMAGE=ubuntu:24.04\nFROM ${BASE_IMAGE}\n") is False
    assert checker("ARG BASE_IMAGE=webpent-base:latest\nFROM ubuntu:24.04\n") is False
    assert checker("ARG BASE_IMAGE=webpent-base:latest\nFROM ${OTHER_IMAGE}\n") is False
