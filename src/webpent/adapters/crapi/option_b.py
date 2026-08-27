"""crAPI-specific Option B object-access profiles.

These profiles are source-backed candidates, not confirmations.  All current
live preconditions are blocked because the approved boundary forbids login,
tokens, and stateful fixture creation, while the local runtime image digest is
not available for reproducibility pinning.
"""

from __future__ import annotations

from re import compile

from webpent.adapters.local_causal_lab.option_b_contract import OptionBCase

CRAPI_ORIGIN = "http://127.0.0.1:8888"
CRAPI_SOURCE_REVISION = "73d309cc8f28bbdeed31dbb35f05dba8354de3c9"
CRAPI_RUNTIME_STATUS = "runtime_digest_unavailable"
CRAPI_SOURCE_FILES = {
    "profile_video": {
        "path": "services/identity/src/main/java/com/crapi/controller/ProfileController.java",
        "sha256": "80c357806f390e28d3ca8f32e12c40fa3d063efcf8038249d5ac5593043677b0",
    },
    "vehicle_location": {
        "path": "services/identity/src/main/java/com/crapi/controller/VehicleController.java",
        "sha256": "c49f5ab14aab7b80386c5e309d6e493360ab86f21d41d939002f1d2961f78789",
    },
    "community_post": {
        "path": "services/community/api/controllers/post_controller.go",
        "sha256": "65200617a05a35c89445e8977be053247dc90b37fe4ebaa060e1ce60e9cd1d3f",
        "route_file_sha256": "0c687eaf66beeb128361f9237882f5ce132472d3feca529e60cbeed29cf5fbfe",
    },
    "mechanic_report": {
        "path": "services/workshop/crapi/mechanic/views.py",
        "sha256": "037f0ebb9045b21a9ee838e5f32fa1be5da17d978f719a8a738f4bbb15426521",
        "route_file_sha256": "71827f3da6fb806172edd044349890dbe2d3e37e92d2a0657ce5f4eacf756ff9",
    },
}


def cases() -> tuple[OptionBCase, ...]:
    common_reason = (
        "Synthetic authenticated ownership state would require login or "
        "token/session injection, which is outside the current GET-only/"
        "no-credentials approval; crAPI runtime digest is unavailable."
    )
    return (
        OptionBCase(
            case_id="crapi.profile_video_object_access.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/identity/api/v2/user/videos/[0-9]{1,12}"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + " Source service also appears owner-scoped; no live BOLA confirmation is inferred.",
            baseline_role="owner_video_control",
            candidate_role="distinct_requester_video_candidate",
            negative_control_roles=("opaque_nonexistent_video",),
        ),
        OptionBCase(
            case_id="crapi.vehicle_location_bola.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/identity/api/v2/vehicle/[0-9a-fA-F-]{36}/location"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + (
                " The source-backed direct UUID lookup is a candidate only; "
                "no authenticated synthetic owner/requester pair is available."
            ),
            baseline_role="owner_vehicle_location_control",
            candidate_role="distinct_requester_vehicle_location_candidate",
            negative_control_roles=("opaque_nonexistent_vehicle",),
        ),
        OptionBCase(
            case_id="crapi.community_post_object_access.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/community/api/v2/community/posts/[0-9]{1,12}"),
            approved_methods=("GET",),
            approved_query_keys=(),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + (
                " Source route is wrapped in authentication middleware; post "
                "creation would also be stateful and is not approved."
            ),
            baseline_role="owner_post_control",
            candidate_role="distinct_requester_post_candidate",
            negative_control_roles=("opaque_nonexistent_post",),
        ),
        OptionBCase(
            case_id="crapi.mechanic_report_object_access.v1",
            target_id="crapi",
            origin=CRAPI_ORIGIN,
            route_pattern=compile(r"/workshop/api/mechanic/mechanic_report"),
            approved_methods=("GET",),
            approved_query_keys=("report_id",),
            track="object_access",
            requires_auth=True,
            requires_target_fixture_injection=True,
            precondition_status="blocked",
            precondition_reason=common_reason
            + (
                " A report must be created before retrieval, but report "
                "creation is stateful and not approved."
            ),
            baseline_role="owner_report_control",
            candidate_role="distinct_requester_report_candidate",
            negative_control_roles=("opaque_nonexistent_report",),
        ),
    )


def validate_profile() -> list[str]:
    errors: list[str] = []
    for case in cases():
        errors.extend(f"{case.case_id}:{error}" for error in case.validate())
    return errors
