from webpent.persistence import DistributedStorageContract


def test_distributed_contract_is_fail_closed_without_explicit_verification():
    contract = DistributedStorageContract(
        database_url="postgresql://db.example/webpent",
        redis_url="rediss://redis.example/0",
        object_store_url="s3://evidence-bucket",
        vector_store_url="pgvector://vector.example/webpent",
    )
    report = contract.as_dict()
    assert report["all_ready"] is False
    assert report["production_qualified"] is False
    assert report["live_qualification_proven"] is False
    assert report["network_probe_performed"] is False
    assert report["migration_performed"] is False
    assert all(item["configured"] for item in report["components"])
    assert all(item["ready"] is False for item in report["components"])


def test_explicit_verification_is_component_scoped_and_non_qualifying():
    contract = DistributedStorageContract(
        database_url="sqlite:///webpent.db",
        redis_url="redis://localhost/0",
        verified_components=("database",),
    )
    readiness = {item.component: item for item in contract.readiness()}
    assert readiness["database"].ready is True
    assert readiness["database"].production_qualified is False
    assert readiness["redis"].ready is False
    assert readiness["evidence_object_store"].reason == "not_configured"


def test_unknown_protocol_fails_closed_without_network_activity():
    contract = DistributedStorageContract(database_url="mysql://db.example/webpent")
    database = contract.readiness()[0]
    assert database.configured is True
    assert database.protocol == "mysql"
    assert database.ready is False
    assert database.reason == "unsupported_protocol"
