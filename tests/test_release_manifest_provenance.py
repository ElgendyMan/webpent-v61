from scripts import check_release_manifest_provenance as provenance


def test_release_manifest_provenance_is_fail_closed_and_reproducible():
    result = provenance.validate()

    assert result["passed"], result
    assert result["manifest_commit"]
    assert result["source_commit"]
    assert result["source_tree"]
