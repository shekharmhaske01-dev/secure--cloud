# HDFS Integration Guide

This guide explains how to use Apache Hadoop HDFS as the storage backend for SecureCloud's encrypted file blocks.

---

## Table of Contents

1. [What is HDFS?](#what-is-hdfs)
2. [Architecture](#architecture)
3. [Setup with Docker](#setup-with-docker)
4. [Manual Setup](#manual-setup)
5. [Configuration Reference](#configuration-reference)
6. [How Encrypted Blocks are Stored](#how-encrypted-blocks-are-stored)
7. [Testing HDFS Storage](#testing-hdfs-storage)
8. [Troubleshooting](#troubleshooting)

---

## What is HDFS?

The **Hadoop Distributed File System (HDFS)** is a distributed file system designed to run on commodity hardware. It provides:

- **Fault tolerance** — data is automatically replicated across nodes
- **High throughput** — optimised for large data transfers
- **Scalability** — add DataNodes to increase capacity
- **Data locality** — computation can move to where data resides

SecureCloud uses HDFS through the **WebHDFS REST API**, which means you don't need Hadoop client libraries on the application server.

---

## Architecture

```
┌──────────────────┐         ┌──────────────────┐
│   SecureCloud    │  HTTP   │   HDFS NameNode   │
│   Application    │────────▶│   (port 9870)     │
│                  │ WebHDFS │   Metadata only   │
└──────────────────┘         └───────┬───────────┘
                                     │
                                     │ manages
                                     ▼
                             ┌──────────────────┐
                             │   HDFS DataNode   │
                             │   (block storage) │
                             │                   │
                             │  /securecloud/    │
                             │    blocks/        │
                             │      <encrypted>  │
                             └──────────────────┘
```

**NameNode:** Manages filesystem metadata (directory tree, block locations).
**DataNode:** Stores actual data blocks. Can be scaled horizontally.

SecureCloud communicates only with the NameNode's WebHDFS endpoint. The NameNode coordinates reads/writes with DataNodes transparently.

---

## Setup with Docker

The easiest way to get HDFS running is with the provided Docker Compose overlay:

### 1. Start the cluster

```bash
docker compose -f docker-compose.yml -f docker-compose.hdfs.yml up -d --build
```

This starts:
- **SecureCloud app** (port 8000)
- **HDFS NameNode** (port 9870 for WebUI/WebHDFS, port 8020 for IPC)
- **HDFS DataNode** (connected to NameNode)

### 2. Wait for HDFS to be ready

The NameNode needs ~30 seconds to initialise. Check the WebUI:

```bash
# Open in browser: http://localhost:9870
# Or check health:
curl -s http://localhost:9870/jmx?qry=Hadoop:service=NameNode,name=NameNodeStatus | python -m json.tool
```

### 3. Initialise directories

```bash
python scripts/setup_hdfs.py --url http://localhost:9870
```

This creates:
- `/securecloud` — root directory
- `/securecloud/blocks` — block storage directory
- Runs a write/read/delete probe to verify cluster health

### 4. Verify

```bash
# Check HDFS storage health via the app
curl http://localhost:8000/healthz
```

---

## Manual Setup

If you have an existing Hadoop cluster:

### 1. Install the Python HDFS library

```bash
pip install 'hdfs>=2.7,<3'
```

### 2. Configure environment variables

```bash
# In .env or environment:
SECURECLOUD_STORAGE_BACKEND=hdfs
HDFS_NAMENODE_URL=http://your-namenode:9870
HDFS_USER=your-hdfs-user
HDFS_ROOT_PATH=/securecloud
```

### 3. Ensure WebHDFS is enabled

In your Hadoop `hdfs-site.xml`:

```xml
<property>
    <name>dfs.webhdfs.enabled</name>
    <value>true</value>
</property>
```

### 4. Create the storage directory

```bash
hdfs dfs -mkdir -p /securecloud/blocks
hdfs dfs -chown your-hdfs-user /securecloud
```

Or use the setup script:

```bash
python scripts/setup_hdfs.py --url http://your-namenode:9870 --user your-hdfs-user
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURECLOUD_STORAGE_BACKEND` | `local` | Set to `hdfs`, `hadoop`, or `webhdfs` |
| `HDFS_NAMENODE_URL` | *(empty)* | WebHDFS endpoint (e.g. `http://namenode:9870`) |
| `HDFS_USER` | `root` | HDFS user for operations |
| `HDFS_ROOT_PATH` | `/securecloud` | Root directory for all SecureCloud data |
| `SECURECLOUD_OBJECT_PREFIX` | `securecloud/blocks` | Sub-path under root for block files |
| `SECURECLOUD_STORAGE_TIMEOUT` | `30` | WebHDFS request timeout (seconds) |

---

## How Encrypted Blocks are Stored

When a file is uploaded to SecureCloud with the HDFS backend:

1. The file is split into fixed-size blocks (default 1 MB)
2. Each block is encrypted with AES-256-GCM using a unique DEK
3. The encrypted block bytes are written to HDFS via WebHDFS
4. Block metadata (storage key, size, hash) is stored in SQLite
5. The DEK is wrapped with the master KEK and stored in SQLite

**HDFS path structure:**

```
/securecloud/                      ← HDFS_ROOT_PATH
  blocks/                          ← SECURECLOUD_OBJECT_PREFIX
    <file_id>/                     ← per-file directory
      block_000.enc                ← encrypted block 0
      block_001.enc                ← encrypted block 1
      ...
```

**Important:** HDFS only ever sees encrypted bytes. Plaintext data never reaches HDFS.

---

## Testing HDFS Storage

### Unit tests (mocked)

The test suite uses the local storage backend by default. HDFS-specific adapter code is tested via the `test_storage.py` pattern.

### Integration test with real HDFS

```bash
# Start HDFS
docker compose -f docker-compose.yml -f docker-compose.hdfs.yml up -d

# Run the deployment test script against the HDFS-backed instance
python scripts/test_deployment.py http://localhost:8000
```

### Manual verification

```bash
# List files in HDFS after uploading
curl -s "http://localhost:9870/webhdfs/v1/securecloud/blocks?op=LISTSTATUS" | python -m json.tool

# Download a raw encrypted block (will be ciphertext)
curl -s -L "http://localhost:9870/webhdfs/v1/securecloud/blocks/<key>?op=OPEN" | xxd | head
```

---

## Troubleshooting

### "HDFS storage is not configured"

**Cause:** One or more required settings are missing.
**Fix:** Ensure all three variables are set:

```bash
HDFS_NAMENODE_URL=http://namenode:9870
HDFS_USER=root
HDFS_ROOT_PATH=/securecloud
```

### "HDFS NameNode could not be reached"

**Cause:** Network connectivity issue.
**Fix:**
- Verify the NameNode is running: `curl http://namenode:9870`
- Check Docker networking: `docker compose logs namenode`
- Ensure port 9870 is accessible

### "The HDFS NameNode is in standby mode"

**Cause:** In an HA cluster, you're connected to the standby NameNode.
**Fix:** Update `HDFS_NAMENODE_URL` to point to the active NameNode, or use a load balancer.

### "HDFS refused the operation (access denied)"

**Cause:** The HDFS user doesn't have permission.
**Fix:**
- Check `HDFS_USER` matches a user with write access
- Disable permission checking for development:
  ```
  HDFS_CONF_dfs_permissions_enabled=false  # in hadoop.env
  ```

### "HDFS health check failed — probe data mismatch"

**Cause:** Data corruption during write or read.
**Fix:**
- Check DataNode health: http://localhost:9870 → Datanodes tab
- Verify replication factor: `HDFS_CONF_dfs_replication=1` for single-node
- Check available disk space on DataNode

### DataNode not connecting

**Cause:** NameNode and DataNode cannot resolve each other's hostnames.
**Fix:** In `hadoop.env`, ensure:

```
HDFS_CONF_dfs_namenode_datanode_registration_ip___hostname___check=false
```
