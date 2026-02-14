# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Standalone NFSv3 server implemented from scratch in C++17 for Linux. Does not use any existing open-source NFS implementation. Implements the full protocol stack per:

- **RFC 1813** — NFS Version 3 Protocol
- **RFC 5531** — ONC RPC v2
- **RFC 4506** — XDR (External Data Representation)

## Build Commands

```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# Run all tests
ctest --test-dir build --output-on-failure

# Run a single test
./build/tests/test_xdr --gtest_filter="XdrCodec.Uint32RoundTrip"

# Run server
sudo ./build/nfsd --export /path/to/share --port 2049
```

## Architecture

The server is layered bottom-up:

```
main.cpp → RpcServer → {MountServer, NfsServer} → Vfs → LocalFs
```

### Layer Details

- **XDR (`src/xdr/`)** — RFC 4506 encoder/decoder. All protocol messages serialize through `XdrEncoder`/`XdrDecoder`. Data is 4-byte aligned, big-endian.

- **ONC RPC (`src/rpc/`)** — TCP server with record marking (4-byte length-prefixed fragments). Dispatches calls by program/version/procedure number. Supports AUTH_NONE and AUTH_SYS. Each client gets its own thread.

- **VFS (`src/vfs/`)** — Abstract `Vfs` interface with `LocalFs` passthrough implementation. File handles are 16 bytes (inode + device). Handle-to-path mapping is cached in-memory with a mutex-protected map.

- **MOUNT (`src/mount/`)** — MOUNT v3 protocol (program 100005). Returns root file handle for exported paths. Both MOUNT and NFS run on the same TCP port (2049).

- **NFS (`src/nfs/`)** — All 22 NFSv3 procedures. `nfs_server.cpp` has dispatch + helpers (fattr3 encoding, post_op_attr, wcc_data). `nfs_procedures.cpp` has the individual procedure implementations.

### Key Design Decisions

- MOUNT and NFS share the same RPC server on port 2049 (no portmapper/rpcbind needed).
- File handles encode raw inode + device numbers. The handle-to-path cache (`handle_to_path_`) is the critical state — stale handles return NFS3ERR_STALE.
- `MSG_NOSIGNAL` is used for TCP sends — this is Linux-only.
- MKNOD returns NFS3ERR_NOTSUPP. READDIRPLUS returns entries without attributes/handles (simplified).
- WCC data always omits pre-op attributes.

## Testing

Unit tests use GoogleTest (fetched via CMake FetchContent). Test files:
- `tests/test_xdr.cpp` — XDR round-trip encoding
- `tests/test_rpc.cpp` — AUTH_SYS parsing, constants
- `tests/test_nfs.cpp` — File handle comparison, NFS constants

Integration testing: mount from a Linux client with `mount -t nfs -o vers=3,proto=tcp <host>:/ /mnt/test`.
