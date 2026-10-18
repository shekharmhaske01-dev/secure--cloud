# Architecture

Detailed architecture documentation for SecureCloud.

---

## System Overview

SecureCloud is a layered Flask application with a clear separation between
presentation (Blueprints + templates), business logic (services), and storage
(pluggable backends).

```
┌─────────────────────────────────────────────────────────────────┐
│                       Presentation Layer                        │
│   ┌──────────┐   ┌──────────────┐   ┌────────────────────┐     │
│   │  auth/   │   │  dashboard/  │   │      files/        │     │
│   │  routes  │   │  routes      │   │  routes (upload/   │     │
│   │          │   │              │   │  download/delete)  │     │
│   └──────────┘   └──────────────┘   └────────────────────┘     │
├─────────────────────────────────────────────────────────────────┤
│                       Service Layer                             │
│   ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐     │
│   │  encryption  │ │   chunking   │ │   file_service     │     │
│   │  AES-256-GCM │ │  split/join  │ │   orchestration    │     │
│   └──────────────┘ └──────────────┘ └────────────────────┘     │
│   ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐     │
│   │ key_manager  │ │  integrity   │ │ storage_service    │     │
│   │ KEK/DEK wrap │ │  SHA-256     │ │ backend dispatch   │     │
│   └──────────────┘ └──────────────┘ └────────────────────┘     │
├─────────────────────────────────────────────────────────────────┤
│                       Storage Layer                             │
│   ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐     │
│   │    Local     │ │  S3 / Neon   │ │       HDFS         │     │
│   │  Filesystem  │ │  (boto3)     │ │  (WebHDFS REST)    │     │
│   └──────────────┘ └──────────────┘ └────────────────────┘     │
├─────────────────────────────────────────────────────────────────┤
│                       Data Layer                                │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │   SQLite (metadata: users, files, blocks, wrapped keys) │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Upload Flow

When a user uploads a file through the web UI:

```
User → POST /files/upload (multipart form)
  │
  ▼
1. Validate file (size, name, CSRF token)
  │
  ▼
2. Generate file metadata (UUID, original filename, MIME type)
  │
  ▼
3. Generate Data Encryption Key (DEK) — 32 random bytes
  │
  ▼
4. Split file into blocks (BLOCK_SIZE bytes each)
  │
  ▼
5. For each block:
  │  a. Build AAD: "SecureCloud/block/v1/<file_id>/<block_index>"
  │  b. Generate 96-bit random nonce
  │  c. Encrypt with AES-256-GCM(DEK, nonce, plaintext, AAD)
  │  d. Compute SHA-256 of ciphertext
  │  e. Upload ciphertext to storage backend
  │  f. Record EncryptedBlock in database
  │
  ▼
6. Wrap DEK with KEK using AES-256-GCM
  │
  ▼
7. Store WrappedKey record in database
  │
  ▼
8. Mark StoredFile status = COMPLETE
  │
  ▼
9. Redirect to file details page
```

---

## Download Flow

When a user downloads a file:

```
User → GET /files/<id>/download
  │
  ▼
1. Verify ownership (user_id matches logged-in user)
  │
  ▼
2. Load StoredFile metadata from database
  │
  ▼
3. Load WrappedKey from database
  │
  ▼
4. Unwrap DEK using KEK (AES-256-GCM decrypt)
  │
  ▼
5. Load all EncryptedBlock records, ordered by block_index
  │
  ▼
6. For each block:
  │  a. Download ciphertext from storage backend
  │  b. Verify SHA-256 against stored hash
  │  c. Build AAD: "SecureCloud/block/v1/<file_id>/<block_index>"
  │  d. Decrypt with AES-256-GCM(DEK, nonce, ciphertext, AAD)
  │
  ▼
7. Concatenate decrypted blocks
  │
  ▼
8. Verify total size matches original_size
  │
  ▼
9. Stream as HTTP response with original filename
```

---

## Encryption Design

### Envelope Encryption

SecureCloud uses a two-tier key hierarchy:

```
┌──────────────────────────────────┐
│  Key Encryption Key (KEK)        │
│  • 256-bit (32 bytes)            │
│  • Base64-encoded in .env        │
│  • ONE per deployment            │
│  • Wraps all DEKs                │
│  • NEVER stored in database      │
└──────────┬───────────────────────┘
           │ wraps/unwraps
           ▼
┌──────────────────────────────────┐
│  Data Encryption Key (DEK)       │
│  • 256-bit (32 bytes)            │
│  • Randomly generated per file   │
│  • Stored WRAPPED (encrypted)    │
│  • Used for all blocks of a file │
└──────────┬───────────────────────┘
           │ encrypts/decrypts
           ▼
┌──────────────────────────────────┐
│  File Blocks                     │
│  • AES-256-GCM encrypted         │
│  • Per-block nonce (96-bit)      │
│  • Per-block AAD (authenticated) │
│  • Stored in backend             │
└──────────────────────────────────┘
```

### Block Format

Each encrypted block is stored as:

```
┌────────┬───────────┬────────────────────────┬─────────┐
│ Nonce  │ Ciphertext│   (encrypted payload)  │   Tag   │
│ 12 B   │ variable  │                        │  16 B   │
└────────┴───────────┴────────────────────────┴─────────┘
```

**AAD (Additional Authenticated Data):**
```
SecureCloud/block/v{version}/{file_id}/{block_index}
```

The AAD is not stored with the ciphertext — it is recomputed during decryption. This binds each block to its file and position, preventing block reordering or substitution attacks.

---

## Storage Abstraction Layer

All storage backends implement the `ObjectStorage` abstract base class:

```python
class ObjectStorage(ABC):
    backend_name: str
    display_name: str
    is_local: bool

    def describe() -> StorageDescription
    def health_check() -> dict
    def upload_object(key, data, ...) -> dict
    def download_object(key) -> bytes
    def delete_object(key) -> bool
    def object_info(key) -> dict
    def list_objects(prefix, limit) -> list[str]
```

### Backend Selection

```python
STORAGE_BACKEND=local    →  LocalObjectStorage   (filesystem)
STORAGE_BACKEND=s3       →  S3ObjectStorage       (boto3)
STORAGE_BACKEND=hdfs     →  HDFSObjectStorage     (WebHDFS)
```

The factory (`create_storage()`) builds the adapter even when configuration is incomplete — the adapter reports `configured=False` and operations raise descriptive errors.

---

## Database Schema

### Users Table (`user`)
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| username | VARCHAR(80) | Unique username |
| email | VARCHAR(120) | Unique email |
| password_hash | VARCHAR(256) | Argon2id hash |
| created_at | DATETIME | Registration time |
| is_active | BOOLEAN | Account active flag |

### StoredFile Table (`stored_file`)
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| file_id | VARCHAR(36) | UUID |
| user_id | INTEGER FK | Owner |
| original_filename | VARCHAR(255) | Original name |
| content_type | VARCHAR(128) | MIME type |
| original_size | BIGINT | Size in bytes |
| block_count | INTEGER | Number of blocks |
| status | VARCHAR(20) | `uploading` / `complete` / `deleted` |
| sha256_hash | VARCHAR(64) | SHA-256 of original |
| created_at | DATETIME | Upload time |

### EncryptedBlock Table (`encrypted_block`)
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| file_id | INTEGER FK | Parent StoredFile |
| block_index | INTEGER | 0-based position |
| storage_key | VARCHAR(512) | Backend object key |
| encrypted_size | INTEGER | Ciphertext size |
| block_hash | VARCHAR(64) | SHA-256 of ciphertext |
| nonce | VARBINARY(12) | AES-GCM nonce |

### WrappedKey Table (`wrapped_key`)
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| file_id | INTEGER FK | Parent StoredFile |
| wrapped_dek | VARBINARY(256) | KEK-encrypted DEK |
| wrap_nonce | VARBINARY(12) | Wrapping nonce |
| wrap_version | INTEGER | Format version |

---

## Error Handling

Storage errors are classified into a hierarchy:

```
StorageError (base)
├── StorageConfigurationError    — invalid config / missing settings
├── StorageNotConfiguredError    — backend not ready
├── StorageObjectNotFoundError   — 404 equivalent
├── StorageAccessDeniedError     — 403 equivalent
├── StorageAuthenticationError   — credential failure
├── StorageTimeoutError          — request timed out
├── StorageUnavailableError      — backend unreachable
├── StorageIntegrityError        — data corruption detected
└── StorageProviderError         — unclassified provider error
```

Each backend adapter translates its native exceptions into this hierarchy so the application layer can handle errors uniformly.
