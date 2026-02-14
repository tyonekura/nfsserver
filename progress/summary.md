# Project Progress Summary

## Completed

### NFSv3 Server Implementation
Standalone NFSv3 server implemented from scratch in C++17 for Linux.

**Protocol stack:**
- XDR encoder/decoder (RFC 4506) — 4-byte aligned, big-endian serialization
- ONC RPC v2 server (RFC 5531) — TCP with record marking, AUTH_NONE/AUTH_SYS
- MOUNT v3 (program 100005) — returns root file handle for exports
- NFS v3 (RFC 1813) — all 22 procedures implemented

**Architecture:**
```
main.cpp → RpcServer → {MountServer, NfsServer} → Vfs → LocalFs
```

**Source layout:**
- `src/xdr/` — XDR codec
- `src/rpc/` — RPC server with per-client threads
- `src/vfs/` — VFS abstraction + local filesystem passthrough
- `src/mount/` — MOUNT v3 service
- `src/nfs/` — NFS v3 service (dispatch + 22 procedures)
- `tests/` — Unit tests (XDR, RPC, NFS) using GoogleTest

### Docker-Based Linux Testing
- `Dockerfile` added for building and testing on Ubuntu 22.04
- All 3 test suites pass on Linux: test_xdr, test_rpc, test_nfs

## Usage

```bash
# Build and test locally (Linux)
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure

# Build and test via Docker
docker build -t nfsd-test . && docker run --rm nfsd-test

# Run server
sudo ./build/nfsd --export /path/to/share --port 2049
```
