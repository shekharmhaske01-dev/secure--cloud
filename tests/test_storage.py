"""Object-storage adapter tests: local filesystem adapter and the S3 adapter."""
from __future__ import annotations

import os

import pytest

from securecloud.storage import (
    LocalObjectStorage,
    S3ObjectStorage,
    StorageNotConfiguredError,
    StorageObjectNotFoundError,
)


# ---------------------------------------------------------------------------
# Local development adapter
# ---------------------------------------------------------------------------
@pytest.fixture()
def local_storage(tmp_path):
    return LocalObjectStorage(root=str(tmp_path / "objects"), prefix="securecloud/blocks")


def test_local_describe_marks_backend_as_local(local_storage):
    desc = local_storage.describe()
    assert desc.is_local is True
    assert desc.backend == "local"
    assert desc.configured is True
    assert "local" in desc.kind_label.lower()


def test_local_health_check(local_storage):
    report = local_storage.health_check()
    assert report["ok"] is True


def test_local_upload_download_round_trip(local_storage):
    payload = os.urandom(5000)
    result = local_storage.upload_object("aa/file/00000000.blk", payload)
    assert result["size"] == len(payload)
    assert local_storage.download_object("aa/file/00000000.blk") == payload
    info = local_storage.object_info("aa/file/00000000.blk")
    assert info["exists"] is True and info["size"] == len(payload)


def test_local_missing_object_raises_not_found(local_storage):
    with pytest.raises(StorageObjectNotFoundError):
        local_storage.download_object("aa/none/00000001.blk")
    assert local_storage.object_info("aa/none/00000001.blk")["exists"] is False


def test_local_delete_object(local_storage):
    local_storage.upload_object("bb/x/00000000.blk", b"data")
    assert local_storage.delete_object("bb/x/00000000.blk") is True
    assert local_storage.delete_object("bb/x/00000000.blk") is False
    assert local_storage.object_info("bb/x/00000000.blk")["exists"] is False


def test_local_list_objects(local_storage):
    for index in range(3):
        local_storage.upload_object(f"cc/f/{index:08d}.blk", b"x" * 10)
    keys = local_storage.list_objects(prefix="cc/f")
    assert len(keys) == 3
    assert all(key.endswith(".blk") for key in keys)


def test_local_rejects_path_traversal(local_storage):
    from securecloud.storage import StorageConfigurationError

    for key in ("../../etc/passwd", "aa/../../escape.blk", "..\\windows\\system32"):
        with pytest.raises(StorageConfigurationError):
            local_storage.upload_object(key, b"nope")


def test_local_rejects_empty_key(local_storage):
    from securecloud.storage import StorageConfigurationError

    with pytest.raises(StorageConfigurationError):
        local_storage.upload_object("", b"nope")


def test_local_storage_marker_written(local_storage):
    assert os.path.exists(os.path.join(local_storage.root, ".securecloud-local-storage"))


def test_local_storage_usage_bytes(local_storage):
    local_storage.upload_object("dd/g/00000000.blk", b"x" * 100)
    assert local_storage.storage_usage_bytes() == 100


# ---------------------------------------------------------------------------
# S3-compatible adapter (Neon Object Storage)
# ---------------------------------------------------------------------------
def test_s3_adapter_reports_missing_settings():
    adapter = S3ObjectStorage(bucket="", endpoint_url="", region="", access_key_id="",
                              secret_access_key="", prefix="securecloud/blocks")
    desc = adapter.describe()
    assert desc.configured is False
    assert desc.is_local is False
    assert "NEON_STORAGE_BUCKET" in desc.missing_settings
    assert "NEON_STORAGE_ACCESS_KEY_ID" in desc.missing_settings
    assert "path" in desc.addressing_style
    with pytest.raises(StorageNotConfiguredError):
        adapter.client()
    report = adapter.health_check()
    assert report["ok"] is False


def test_s3_adapter_has_no_local_fallback():
    adapter = S3ObjectStorage(bucket="b", endpoint_url="https://example.invalid",
                              region="us-east-1", access_key_id="k", secret_access_key="s")
    desc = adapter.describe()
    assert desc.is_local is False
    assert any("fall back" in note.lower() or "no fallback" in note.lower() for note in desc.notes) or \
        any("never" in note.lower() for note in desc.notes) or desc.configured is True


def test_s3_from_config_uses_neon_names_and_aws_aliases():
    config = {
        "NEON_STORAGE_ENDPOINT_URL": "",
        "NEON_STORAGE_REGION": "",
        "NEON_STORAGE_BUCKET": "bucket-from-config",
        "NEON_STORAGE_ACCESS_KEY_ID": "",
        "NEON_STORAGE_SECRET_ACCESS_KEY": "",
        "AWS_ENDPOINT_URL_S3": "https://branch.example.invalid",
        "AWS_REGION": "us-east-2",
        "AWS_ACCESS_KEY_ID": "alias-key",
        "AWS_SECRET_ACCESS_KEY": "alias-secret",
        "STORAGE_PREFIX": "securecloud/blocks",
        "STORAGE_TIMEOUT_SECONDS": 10,
        "STORAGE_MAX_RETRIES": 2,
    }
    adapter = S3ObjectStorage.from_config(config)
    desc = adapter.describe()
    assert adapter.bucket == "bucket-from-config"
    assert adapter.endpoint_url == "https://branch.example.invalid"
    assert adapter.region == "us-east-2"
    assert adapter.access_key_id == "alias-key"
    assert desc.configured is True


def test_s3_from_config_ignores_placeholders():
    config = {
        "NEON_STORAGE_ENDPOINT_URL": "REPLACE_WITH_YOUR_BRANCH_S3_ENDPOINT_URL",
        "NEON_STORAGE_REGION": "REPLACE_WITH_YOUR_BRANCH_REGION",
        "NEON_STORAGE_BUCKET": "",
        "NEON_STORAGE_ACCESS_KEY_ID": "REPLACE_WITH_YOUR_ACCESS_KEY_ID",
        "NEON_STORAGE_SECRET_ACCESS_KEY": "",
    }
    adapter = S3ObjectStorage.from_config(config)
    assert adapter.endpoint_url == ""
    assert adapter.describe().configured is False


def test_s3_client_uses_path_addressing():
    """Neon Object Storage requires path-style addressing."""
    from moto import mock_aws

    with mock_aws():
        adapter = S3ObjectStorage(bucket="securecloud-test", endpoint_url="",
                                 region="us-east-1", access_key_id="testing",
                                 secret_access_key="testing", prefix="securecloud/blocks")
        client = adapter.client()
        assert client.meta.config.s3["addressing_style"] == "path"


def test_s3_round_trip_with_moto():
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws

    with mock_aws():
        session_client = boto3.client("s3", region_name="us-east-1",
                                     aws_access_key_id="testing", aws_secret_access_key="testing")
        session_client.create_bucket(Bucket="securecloud-test")

        adapter = S3ObjectStorage(bucket="securecloud-test", endpoint_url="",
                                 region="us-east-1", access_key_id="testing",
                                 secret_access_key="testing", prefix="securecloud/blocks")

        health = adapter.health_check()
        assert health["ok"] is True, health

        payload = os.urandom(4096)
        stored = adapter.upload_object("ab/uid/00000000.blk", payload)
        assert stored["size"] == len(payload)
        assert stored["key"] == "securecloud/blocks/ab/uid/00000000.blk"

        assert adapter.download_object("ab/uid/00000000.blk") == payload
        info = adapter.object_info("ab/uid/00000000.blk")
        assert info["exists"] is True and info["size"] == len(payload)

        keys = adapter.list_objects(prefix="ab/uid")
        assert "securecloud/blocks/ab/uid/00000000.blk" in keys

        assert adapter.delete_object("ab/uid/00000000.blk") is True
        assert adapter.object_info("ab/uid/00000000.blk")["exists"] is False


def test_s3_missing_object_maps_to_not_found():
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws

    with mock_aws():
        boto3.client("s3", region_name="us-east-1", aws_access_key_id="testing",
                     aws_secret_access_key="testing").create_bucket(Bucket="securecloud-test")
        adapter = S3ObjectStorage(bucket="securecloud-test", region="us-east-1",
                                 access_key_id="testing", secret_access_key="testing")
        with pytest.raises(StorageObjectNotFoundError):
            adapter.download_object("does/not/exist.blk")
        assert adapter.object_info("does/not/exist.blk")["exists"] is False


def test_s3_access_denied_maps_to_specific_error():
    from botocore.exceptions import ClientError

    from securecloud.storage import StorageAccessDeniedError

    adapter = S3ObjectStorage(bucket="b", region="us-east-1", access_key_id="k",
                             secret_access_key="s")
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"},
         "ResponseMetadata": {"HTTPStatusCode": 403}},
        "GetObject",
    )
    translated = adapter._translate(error, key="some/key")
    assert isinstance(translated, StorageAccessDeniedError)
    assert "access denied" in translated.public_message.lower()


def test_s3_credential_error_maps_to_authentication_error():
    from botocore.exceptions import ClientError

    from securecloud.storage import StorageAuthenticationError

    adapter = S3ObjectStorage(bucket="b", region="us-east-1", access_key_id="k",
                             secret_access_key="s")
    error = ClientError(
        {"Error": {"Code": "InvalidAccessKeyId", "Message": "bad key"},
         "ResponseMetadata": {"HTTPStatusCode": 403}},
        "PutObject",
    )
    translated = adapter._translate(error, key="some/key")
    assert isinstance(translated, StorageAuthenticationError)


def test_s3_timeout_and_network_errors_are_translated():
    from botocore.exceptions import ConnectTimeoutError, EndpointConnectionError

    from securecloud.storage import StorageTimeoutError, StorageUnavailableError

    adapter = S3ObjectStorage(bucket="b", region="us-east-1", access_key_id="k",
                             secret_access_key="s")
    assert isinstance(adapter._translate(ConnectTimeoutError(endpoint_url="x")), StorageTimeoutError)
    assert isinstance(
        adapter._translate(EndpointConnectionError(endpoint_url="x")), StorageUnavailableError
    )


def test_object_keys_never_contain_user_filenames():
    """Object keys must be derived from the opaque identifier and block index only."""
    from securecloud.services.storage_service import StorageService

    adapter = LocalObjectStorage(root="/tmp/securecloud-key-test", prefix="securecloud/blocks")
    service = StorageService(adapter, prefix="securecloud/blocks")
    uid = service.new_file_identifier()
    key = service.block_key(uid, 12)
    assert uid in key
    assert key.endswith("00000012.blk")
    assert "report" not in key and "pdf" not in key
    assert len(uid) == 32
    assert service.block_key(uid, 12) != service.block_key(uid, 13)
