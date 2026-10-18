#!/usr/bin/env python3
"""Initialise the HDFS directories required by SecureCloud.

Usage:
    python scripts/setup_hdfs.py [--url http://namenode:9870] [--user root]

The script connects to the HDFS NameNode via WebHDFS, creates the storage
directory tree, and runs a quick write/read/delete probe to confirm the
cluster is healthy.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

try:
    from hdfs import InsecureClient
    from hdfs.util import HdfsError
except ImportError:
    sys.exit(
        "ERROR: 'hdfs' package not installed.  Run:  pip install 'hdfs>=2.7,<3'"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialise HDFS for SecureCloud")
    parser.add_argument(
        "--url",
        default=os.getenv("HDFS_NAMENODE_URL", "http://localhost:9870"),
        help="WebHDFS NameNode URL (default: $HDFS_NAMENODE_URL or http://localhost:9870)",
    )
    parser.add_argument(
        "--user",
        default=os.getenv("HDFS_USER", "root"),
        help="HDFS user name (default: $HDFS_USER or root)",
    )
    parser.add_argument(
        "--root",
        default=os.getenv("HDFS_ROOT_PATH", "/securecloud"),
        help="HDFS root path for SecureCloud (default: $HDFS_ROOT_PATH or /securecloud)",
    )
    args = parser.parse_args()

    print(f"[setup_hdfs] Connecting to {args.url} as '{args.user}' ...")
    client = InsecureClient(args.url, user=args.user, timeout=15)

    # 1. Create directories
    dirs = [args.root, f"{args.root}/blocks"]
    for d in dirs:
        print(f"[setup_hdfs] Creating directory: {d}")
        client.makedirs(d)

    # 2. Probe: write → read → delete
    probe_path = f"{args.root}/.setup-probe-{int(time.time())}"
    probe_data = f"SecureCloud probe at {time.time()}".encode()

    print(f"[setup_hdfs] Writing probe file: {probe_path}")
    with client.write(probe_path, overwrite=True) as writer:
        writer.write(probe_data)

    print(f"[setup_hdfs] Reading probe file back ...")
    with client.read(probe_path) as reader:
        read_back = reader.read()

    if read_back != probe_data:
        sys.exit("ERROR: Probe data mismatch — HDFS returned different bytes!")

    print(f"[setup_hdfs] Deleting probe file ...")
    client.delete(probe_path)

    print()
    print("=" * 60)
    print("  HDFS is ready for SecureCloud!")
    print(f"  NameNode URL : {args.url}")
    print(f"  HDFS User    : {args.user}")
    print(f"  Root Path    : {args.root}")
    print("=" * 60)


if __name__ == "__main__":
    main()
