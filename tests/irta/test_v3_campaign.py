import pytest

from webpent.irta.v3 import LocalReadOnlyCampaign, build_independent_targets


@pytest.mark.asyncio
async def test_campaign_discovers_and_observes_each_target() -> None:
    for target in build_independent_targets():
        result = await LocalReadOnlyCampaign(target).run()
        assert result.target_id == target.target_id
        assert result.routes
        assert result.observations
        assert all(route.method in {"GET", "HEAD", "OPTIONS"} for route in result.routes)
        assert all(
            observation.status_code in {200, 401, 403, 404}
            for observation in result.observations
        )
        assert all(observation.body_digest for observation in result.observations)


@pytest.mark.asyncio
async def test_campaign_does_not_expose_truth_or_send_mutation_methods() -> None:
    target = build_independent_targets()[0]
    result = await LocalReadOnlyCampaign(target).run()
    assert all(
        observation.method in {"GET", "HEAD", "OPTIONS"}
        for observation in result.observations
    )
    assert all("expected" not in observation.__dict__ for observation in result.observations)
    assert all("vulnerab" not in observation.__dict__ for observation in result.observations)
