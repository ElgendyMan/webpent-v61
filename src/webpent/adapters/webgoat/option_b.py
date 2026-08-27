"""WebGoat-specific Option B case contract.

The profile is source-backed but intentionally reports both approved-track and
runnable-precondition states.  Current GET-only approval cannot establish the
required IDOR session or inject a target-local canary into the live handler.
"""

from __future__ import annotations

from re import compile

from webpent.adapters.local_causal_lab.option_b_contract import OptionBCase

WEBGOAT_ORIGIN = "http://127.0.0.1:8080"
WEBGOAT_SOURCE_REVISION = "7517acca95d9851da706452454c223dd13545ef4"
WEBGOAT_SOURCE_FILES = {
    "idor_view": {
        "path": "src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java",
        "sha256": "305cb5c0fc8d63a0b8bb4f48f4ebc6982ee332bc11c7f1dcc0ad248a3f6ac3e6",
    },
    "path_traversal_controller": {
        "path": "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java",
        "sha256": "71d8b73188716f253ffafff4de58ec4f9955b75048bf2bdb00ee07362b093ea2",
    },
    "path_traversal_source": {
        "path": "src/main/java/org/owasp/webgoat/lessons/pathtraversal/PathTraversal.java",
        "sha256": "d8298e3c3ee511969c34f7611b5047d5563021cba4a944bf09bc8b5bf0280a6d",
    },
}


def cases() -> tuple[OptionBCase, ...]:
    return (
        OptionBCase(
            case_id="webgoat.idor.view_other_profile.v1",
            target_id="owasp_webgoat",
            origin=WEBGOAT_ORIGIN,
            route_pattern=compile(r"/WebGoat/IDOR/profile/[A-Za-z0-9_-]{1,64}"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="idor",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=(
                "GET-only approval cannot create the required LessonSession; "
                "POST login and built-in lesson credentials are not approved."
            ),
            baseline_role="requester_own_profile",
            candidate_role="requester_other_synthetic_profile",
            negative_control_roles=("opaque_nonexistent_profile",),
        ),
        OptionBCase(
            case_id="webgoat.path_traversal.v1",
            target_id="owasp_webgoat",
            origin=WEBGOAT_ORIGIN,
            route_pattern=compile(r"/WebGoat/PathTraversal/random-picture"),
            approved_methods=("GET",),
            approved_query_keys=("id",),
            track="path_traversal",
            requires_auth=False,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=(
                "The live handler seeds its own lesson file and rejects raw "
                "traversal markers; no source-backed target-local disposable "
                "canary injection route is available without broad filesystem risk."
            ),
            baseline_role="approved_cat_picture_control",
            candidate_role="bounded_encoded_canary_candidate",
            negative_control_roles=("invalid_opaque_id", "sibling_file_control"),
        ),
    )


def validate_profile() -> list[str]:
    errors: list[str] = []
    for case in cases():
        errors.extend(f"{case.case_id}:{error}" for error in case.validate())
    return errors
