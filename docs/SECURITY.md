# Security Documentation

Comprehensive security analysis and design documentation for SecureCloud.

---

## Threat Model

SecureCloud protects user files against:

| Threat | Mitigation |
|--------|-----------|
| **Stolen storage media** | Files encrypted at rest with AES-256-GCM |
| **Database breach** | DEKs stored wrapped (encrypted by KEK); passwords hashed with Argon2id |
| **Man-in-the-middle** | HTTPS enforced in production; secure cookie flags |
| **Cross-site request forgery** | CSRF tokens on all state-changing endpoints |
| **Brute-force login** | Rate limiting on auth endpoints |
| **Session hijacking** | HttpOnly, Secure, SameSite=Lax cookies; session expiry |
| **Block reordering** | Authenticated encryption with per-block AAD |
| **Data corruption** | SHA-256 integrity checks on all blocks |
| **Unauthorised access** | Ownership checks on all file operations |

---

## Encryption Details

### Algorithm: AES-256-GCM

- **Key size:** 256 bits (32 bytes)
- **Nonce:** 96 bits (12 bytes), randomly generated per block
- **Tag:** 128 bits (16 bytes), appended to ciphertext
- **Mode:** Galois/Counter Mode — provides both confidentiality and authenticity

### Why AES-256-GCM?

1. **Authenticated encryption** — detects tampering without a separate MAC
2. **Hardware acceleration** — AES-NI instructions on modern CPUs
3. **Industry standard** — used in TLS 1.3, SSH, IPsec
4. **No padding oracle** — stream cipher mode eliminates padding attacks

### Per-Block AAD

Each block includes Additional Authenticated Data that is verified during
decryption but not stored in the ciphertext:

```
AAD = b"SecureCloud/block/v{version}/{file_id}/{block_index}"
```

This prevents:
- **Block substitution** — swapping blocks between files
- **Block reordering** — moving block 3 to position 1
- **Version downgrade** — changing the format version

---

## Key Management

### Key Encryption Key (KEK)

- **Source:** Environment variable `SECURECLOUD_KEY_ENCRYPTION_KEY`
- **Format:** Base64-encoded 32 bytes
- **Lifecycle:** Set once at deployment; never changes during normal operation
- **Storage:** ONLY in environment / secrets manager — never in database
- **Loss impact:** ALL encrypted files become permanently unrecoverable

### Data Encryption Key (DEK)

- **Generation:** `os.urandom(32)` — 32 cryptographically random bytes per file
- **Usage:** Encrypts all blocks of a single file
- **Storage:** Wrapped (encrypted) by KEK, stored in `wrapped_key` table
- **Wrapping:** AES-256-GCM with its own nonce

### Key Hierarchy

```
Environment Variable
       │
       ▼
┌──────────────┐
│     KEK      │  (1 per deployment)
│  32 bytes    │
└──────┬───────┘
       │ wraps
       ▼
┌──────────────┐
│     DEK      │  (1 per file)
│  32 bytes    │
│  (wrapped)   │
└──────┬───────┘
       │ encrypts
       ▼
┌──────────────┐
│  File Blocks │  (N per file)
│  AES-256-GCM │
└──────────────┘
```

---

## Authentication

### Argon2id Password Hashing

SecureCloud uses **Argon2id**, the winner of the Password Hashing Competition:

- **Type:** Argon2id (hybrid — resists both GPU and side-channel attacks)
- **Library:** `argon2-cffi`
- **Parameters:** Library defaults (automatically tuned for the hardware)
- **Salt:** Randomly generated per password

### Why Argon2id?

| Feature | Argon2id | bcrypt | PBKDF2 |
|---------|----------|--------|--------|
| GPU resistance | ✅ High | ⚠️ Moderate | ❌ Low |
| Side-channel resistance | ✅ Yes | ❌ No | ❌ No |
| Memory hardness | ✅ Yes | ⚠️ Limited | ❌ No |
| Modern standard | ✅ PHC winner | ⚠️ Legacy | ⚠️ Legacy |

---

## Session Security

| Setting | Value | Purpose |
|---------|-------|---------|
| `SESSION_COOKIE_HTTPONLY` | `True` | Prevents JavaScript access to session cookie |
| `SESSION_COOKIE_SECURE` | `True` (prod) | Cookie only sent over HTTPS |
| `SESSION_COOKIE_SAMESITE` | `Lax` | Prevents CSRF via cross-origin requests |
| `PERMANENT_SESSION_LIFETIME` | 12 hours | Session expiry |
| `SESSION_COOKIE_NAME` | `securecloud_session` | Custom name (avoids default fingerprinting) |

---

## CSRF Protection

All state-changing endpoints (POST) require a CSRF token:

1. Server generates a random token and embeds it in the HTML form
2. Client submits the token with the form data
3. Server validates the token matches the session-bound value
4. Mismatched or missing tokens result in 400 Bad Request

**Implementation:** Flask-WTF with `CSRFProtect`

---

## Rate Limiting

Configurable per-endpoint throttling prevents abuse:

| Endpoint | Default Limit | Purpose |
|----------|--------------|---------|
| Login | 10/minute | Prevent brute-force |
| Register | 5/hour | Prevent mass registration |
| Upload | 60/hour | Prevent storage abuse |
| Download | 240/hour | Prevent scraping |
| Sensitive | 30/hour | Protect admin actions |
| Global | 1000/hour | Overall protection |

**Implementation:** Flask-Limiter with in-memory storage (configurable to Redis).

---

## Security Headers

When `SECURITY_HEADERS_ENABLED=true` (default), the following headers are set on all responses:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |
| `Content-Security-Policy` | `default-src 'self'` | Restrict resource loading |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer leakage |
| `Strict-Transport-Security` | `max-age=31536000` | Enforce HTTPS (prod) |
| `Permissions-Policy` | Restrictive | Disable unnecessary APIs |

---

## Data Protection

### At Rest
- All file blocks are AES-256-GCM encrypted before storage
- DEKs are wrapped with the KEK before database storage
- Passwords are Argon2id hashed
- The KEK exists only in the environment, never in the database

### In Transit
- HTTPS enforced in production (via platform or reverse proxy)
- Secure cookie flags prevent session token leakage
- HSTS header tells browsers to always use HTTPS

### On Deletion
- Encrypted blocks are removed from the storage backend
- Database records are marked as `deleted`
- The wrapped DEK becomes useless once blocks are removed

### Storage Backend Security
- **Local:** Relies on filesystem permissions
- **S3:** Uses IAM credentials; supports server-side encryption (SSE)
- **HDFS:** Uses HDFS permissions; data encrypted by SecureCloud before upload

---

## Security Recommendations

### For Development
1. Use the development configuration (`FLASK_ENV=development`)
2. Generate a test KEK with `python scripts/generate_encryption_key.py`
3. Don't use production secrets in development

### For Production
1. Generate strong, unique `SECRET_KEY` and `SECURECLOUD_KEY_ENCRYPTION_KEY`
2. **Back up the KEK** — losing it means ALL files are lost forever
3. Set `FLASK_ENV=production`
4. Enable HTTPS and set `SECURECLOUD_SESSION_COOKIE_SECURE=true`
5. Use a secrets manager for environment variables
6. Restrict database file permissions
7. Monitor rate limiting logs for abuse patterns
8. Regularly update dependencies for security patches
