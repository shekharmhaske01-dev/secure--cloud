"""S3-compatible cloud object storage adapter (Neon Object Storage).

Neon Object Storage speaks the S3 API directly and requires **path-style**
addressing, so the boto3 client is created with
``addressing_style="path"``.  The endpoint, region and credentials are read
from the environment (see ``.env.example``); nothing is hardcoded and no
endpoint is invented.

Errors are translated into specific exceptions so the application can react
(missing object, access denied, timeout, provider failure) instead of
collapsing everything into a generic error.  There is no fallback to local
storage: a failed cloud operation is reported as a failure.
"""
from __future__ import annotations

import botocore
from botocore.config import Config as BotoConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
    PartialCredentialsError,
    ReadTimeoutError,
    SSLError,
)

from securecloud.storage.base import (
    ObjectStorage,
    StorageAccessDeniedError,
    StorageAuthenticationError,
    StorageConfigurationError,
    StorageDescription,
    StorageNotConfiguredError,
    StorageObjectNotFoundError,
    StorageProviderError,
    StorageTimeoutError,
    StorageUnavailableError,
)

# Error codes that mean "the object is not there".
_NOT_FOUND_CODES = {"NoSuchKey", "NoSuchBucket", "NotFound", "404", "NoSuchUpload"}
_ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "403", "AllAccessDisabled", "InvalidObjectState"}
_CREDENTIAL_CODES = {
    "InvalidAccessKeyId",
    "SignatureDoesNotMatch",
    "ExpiredToken",
    "InvalidToken",
    "AuthorizationHeaderMalformed",
    "UnrecognizedClientException",
}

REQUIRED_SETTINGS = (
    "NEON_STORAGE_BUCKET",
    "NEON_STORAGE_ACCESS_KEY_ID",
    "NEON_STORAGE_SECRET_ACCESS_KEY",
    "NEON_STORAGE_REGION",
)


class S3ObjectStorage(ObjectStorage):
    """S3-compatible backend used for Neon Object Storage."""

    backend_name = "s3"
    display_name = "S3-compatible object storage (Neon Object Storage)"
    is_local = False

    def __init__(self, *, bucket: str = "", endpoint_url: str = "", region: str = "",
                 access_key_id: str = "", secret_access_key: str = "",
                 prefix: str = "", timeout: int = 30, max_attempts: int = 3,
                 verify_tls: bool = True, source_map: dict | None = None):
        self.bucket = (bucket or "").strip()
        self.endpoint_url = (endpoint_url or "").strip()
        self.region = (region or "").strip() or "us-east-1"
        self.access_key_id = (access_key_id or "").strip()
        self.secret_access_key = (secret_access_key or "").strip()
        self.prefix = (prefix or "").strip("/")
        self.timeout = max(int(timeout or 30), 1)
        self.max_attempts = max(int(max_attempts or 3), 1)
        self.verify_tls = bool(verify_tls)
        self.source_map = dict(source_map or {})
        self._client = None
        # Set when a region was supplied explicitly (as opposed to the
        # fallback default) so the configuration check can report it.
        self._region_explicit = bool((region or "").strip())

        missing = [name for name in REQUIRED_SETTINGS if not self._value_for(name)]
        self.missing_settings = tuple(missing)
        self._configured = not missing

    # --- configuration ----------------------------------------------------
    def _value_for(self, setting: str) -> str:
        mapping = {
            "NEON_STORAGE_BUCKET": self.bucket,
            "NEON_STORAGE_ACCESS_KEY_ID": self.access_key_id,
            "NEON_STORAGE_SECRET_ACCESS_KEY": self.secret_access_key,
            "NEON_STORAGE_REGION": self.region if self.region != "us-east-1" or self._has_explicit_region else "",
        }
        return mapping.get(setting, "")

    @property
    def _has_explicit_region(self) -> bool:
        return bool(self._region_explicit)

    @classmethod
    def from_config(cls, config) -> "S3ObjectStorage":
        """Build the adapter from an application config mapping.

        ``NEON_STORAGE_*`` variables take precedence; the documented AWS alias
        names (which Neon injects in its own runtime) are used as a fallback so
        existing configurations keep working.
        """
        def pick(primary: str, alias: str) -> str:
            value = (config.get(primary) or "").strip()
            if value and not _looks_like_placeholder(value):
                return value
            return (config.get(alias) or "").strip()

        endpoint = pick("NEON_STORAGE_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3")
        region = pick("NEON_STORAGE_REGION", "AWS_REGION")
        bucket = (config.get("NEON_STORAGE_BUCKET") or "").strip()
        access = pick("NEON_STORAGE_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")
        secret = pick("NEON_STORAGE_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY")

        storage = cls(
            bucket=bucket,
            endpoint_url=endpoint,
            region=region or "us-east-1",
            access_key_id=access,
            secret_access_key=secret,
            prefix=config.get("STORAGE_PREFIX") or config.get("SECURECLOUD_OBJECT_PREFIX") or "",
            timeout=config.get("STORAGE_TIMEOUT_SECONDS", 30),
            max_attempts=config.get("STORAGE_MAX_RETRIES", 3),
        )
        storage._region_explicit = bool(region)
        if not region:
            storage.missing_settings = tuple(dict.fromkeys(list(storage.missing_settings) + ["NEON_STORAGE_REGION"]))
            storage._configured = False
        return storage

    # --- description ------------------------------------------------------
    def describe(self) -> StorageDescription:
        notes = [
            "Path-style addressing is required by Neon Object Storage.",
            "Encrypted blocks only: plaintext is never uploaded.",
        ]
        if self.endpoint_url:
            notes.append("Endpoint supplied through configuration (branch-scoped).")
        else:
            notes.append("No endpoint set: the provider default endpoint is used.")
        if not self._configured:
            notes.append(
                "Configuration incomplete - cloud operations are disabled. "
                "SecureCloud will not fall back to local storage."
            )
        return StorageDescription(
            backend=self.backend_name,
            display_name=self.display_name,
            is_local=False,
            configured=self._configured,
            bucket=self.bucket or "(not set)",
            endpoint=self.endpoint_url or "(provider default)",
            region=self.region or "(not set)",
            addressing_style="path",
            prefix=self.prefix,
            location=f"s3://{self.bucket or '(no bucket)'}/{self.prefix}".rstrip("/"),
            missing_settings=self.missing_settings,
            notes=tuple(notes),
        )

    # --- client -----------------------------------------------------------
    def _require_configured(self) -> None:
        if not self._configured:
            raise StorageNotConfiguredError(
                "Cloud object storage is not fully configured. Missing settings: "
                + ", ".join(self.missing_settings)
                + ". Set them in your environment (.env) - SecureCloud does not fall "
                  "back to local storage.",
                detail="missing: " + ",".join(self.missing_settings),
            )

    def client(self):
        self._require_configured()
        if self._client is None:
            boto_config = BotoConfig(
                connect_timeout=self.timeout,
                read_timeout=self.timeout,
                retries={"max_attempts": self.max_attempts, "mode": "standard"},
                s3={"addressing_style": "path"},  # required by Neon Object Storage
                signature_version="s3v4",
                user_agent_extra="SecureCloud/1.0",
            )
            kwargs = {
                "service_name": "s3",
                "region_name": self.region,
                "aws_access_key_id": self.access_key_id,
                "aws_secret_access_key": self.secret_access_key,
                "config": boto_config,
                "verify": self.verify_tls,
            }
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            self._client = botocore.session.get_session().create_client(**kwargs)
        return self._client

    def reset_client(self) -> None:
        self._client = None

    # --- error translation ------------------------------------------------
    def _translate(self, exc: Exception, key: str = "") -> Exception:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {}) or {}
            code = str(error.get("Code", ""))
            status = (exc.response.get("ResponseMetadata", {}) or {}).get("HTTPStatusCode")
            if code in _NOT_FOUND_CODES or status == 404:
                return StorageObjectNotFoundError(key, detail=f"{code} ({status})")
            # Check the credential codes first: an invalid or expired key also
            # comes back as HTTP 403, and reporting it as "access denied" would
            # send the operator looking at bucket policies instead of the key.
            if code in _CREDENTIAL_CODES:
                return StorageAuthenticationError(
                    "Object storage rejected the configured credentials.",
                    detail=f"{code} ({status})",
                )
            if code in _ACCESS_DENIED_CODES or status == 403:
                return StorageAccessDeniedError(
                    "Object storage refused the operation (access denied). Check the "
                    "credential's storage scopes and bucket permissions.",
                    detail=f"{code} ({status})",
                )
            return StorageProviderError(
                "Object storage returned an error for this operation.",
                detail=f"{code} ({status})",
            )
        if isinstance(exc, (ConnectTimeoutError, ReadTimeoutError)):
            return StorageTimeoutError(
                "Object storage did not respond in time. Please try again.",
                detail=type(exc).__name__,
            )
        if isinstance(exc, (EndpointConnectionError, ConnectionClosedError, SSLError)):
            return StorageUnavailableError(
                "Object storage could not be reached. Check the endpoint URL and network.",
                detail=type(exc).__name__,
            )
        if isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
            return StorageNotConfiguredError(
                "No usable object-storage credentials were found.",
                detail=type(exc).__name__,
            )
        if isinstance(exc, ParamValidationError):
            return StorageConfigurationError(
                "Object storage request could not be built from the current configuration.",
                detail=type(exc).__name__,
            )
        if isinstance(exc, BotoCoreError):
            return StorageUnavailableError(
                "Object storage client error.", detail=type(exc).__name__
            )
        return exc

    # --- operations -------------------------------------------------------
    def health_check(self) -> dict:
        if not self._configured:
            return {
                "ok": False,
                "message": "Cloud object storage is not configured. Missing: "
                           + ", ".join(self.missing_settings),
                "details": {"missing_settings": list(self.missing_settings)},
            }
        try:
            client = self.client()
            client.head_bucket(Bucket=self.bucket)
            listing = client.list_objects_v2(Bucket=self.bucket, Prefix=self.prefix, MaxKeys=1)
            return {
                "ok": True,
                "message": f"Connected to bucket '{self.bucket}'.",
                "details": {
                    "bucket": self.bucket,
                    "endpoint": self.endpoint_url or "(provider default)",
                    "region": self.region,
                    "addressing_style": "path",
                    "prefix": self.prefix,
                    "object_count_sampled": listing.get("KeyCount", 0),
                },
            }
        except Exception as exc:
            translated = self._translate(exc)
            return {
                "ok": False,
                "message": getattr(translated, "public_message", "Object storage check failed."),
                "details": {"category": getattr(translated, "category", "unknown")},
            }

    def upload_object(self, key: str, data: bytes, *, content_type: str = "application/octet-stream",
                      metadata: dict | None = None) -> dict:
        self._require_configured()
        full_key = self._full_key(key)
        try:
            response = self.client().put_object(
                Bucket=self.bucket,
                Key=full_key,
                Body=data,
                ContentType=content_type,
                Metadata={str(k): str(v) for k, v in (metadata or {}).items()},
            )
        except Exception as exc:
            raise self._translate(exc, key=full_key) from exc
        return {
            "key": full_key,
            "size": len(data),
            "etag": (response.get("ETag") or "").strip('"'),
        }

    def download_object(self, key: str) -> bytes:
        self._require_configured()
        full_key = self._full_key(key)
        try:
            response = self.client().get_object(Bucket=self.bucket, Key=full_key)
            body = response["Body"].read()
        except Exception as exc:
            raise self._translate(exc, key=full_key) from exc
        return body

    def delete_object(self, key: str) -> bool:
        self._require_configured()
        full_key = self._full_key(key)
        try:
            self.client().delete_object(Bucket=self.bucket, Key=full_key)
        except Exception as exc:
            raise self._translate(exc, key=full_key) from exc
        return True

    def object_info(self, key: str) -> dict:
        self._require_configured()
        full_key = self._full_key(key)
        try:
            response = self.client().head_object(Bucket=self.bucket, Key=full_key)
        except Exception as exc:
            translated = self._translate(exc, key=full_key)
            if isinstance(translated, StorageObjectNotFoundError):
                return {"exists": False, "size": None, "etag": None}
            raise translated from exc
        return {
            "exists": True,
            "size": response.get("ContentLength"),
            "etag": (response.get("ETag") or "").strip('"'),
        }

    def list_objects(self, prefix: str = "", limit: int = 1000) -> list[str]:
        self._require_configured()
        search_prefix = self._full_key(prefix) if prefix else (self.prefix + "/" if self.prefix else "")
        keys: list[str] = []
        try:
            paginator = self.client().get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=search_prefix,
                                           PaginationConfig={"PageSize": min(limit, 1000)}):
                for item in page.get("Contents", []) or []:
                    keys.append(item["Key"])
                    if len(keys) >= limit:
                        return keys
        except Exception as exc:
            raise self._translate(exc) from exc
        return keys

    # --- helpers ----------------------------------------------------------
    def _full_key(self, key: str) -> str:
        clean = (key or "").strip("/")
        if not clean:
            raise StorageConfigurationError("An object key is required.")
        return f"{self.prefix}/{clean}" if self.prefix else clean

    def strip_prefix(self, key: str) -> str:
        if self.prefix and key.startswith(self.prefix + "/"):
            return key[len(self.prefix) + 1:]
        return key


def _looks_like_placeholder(value: str) -> bool:
    upper = (value or "").upper()
    return any(marker in upper for marker in ("REPLACE_WITH", "CHANGEME", "CHANGE_ME", "YOUR_"))
