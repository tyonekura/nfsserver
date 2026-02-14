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
- `tests/` — Unit tests (XDR, RPC, NFS, VFS) using GoogleTest

### Docker-Based Linux Testing
- `Dockerfile` added for building and testing on Ubuntu 22.04
- All 4 test suites pass on Linux: test_xdr, test_rpc, test_nfs, test_vfs

### Bug Fixes & Improvements (6 Phases)

**Phase 1 — Build Infrastructure**
- Enabled `-Wall -Wextra -Wpedantic` compiler warnings
- Fixed all existing warnings (unused parameters, variables)

**Phase 2 — XDR Tests**
- Added int64 round-trip, skip() with padding, empty opaque tests

**Phase 3 — RPC Critical Bugs**
- Fixed data race on `threads_` vector (added mutex)
- Implemented multi-fragment RPC record reassembly (RFC 5531 §11)
- Fixed RPC version mismatch reply (MSG_DENIED/RPC_MISMATCH per RFC)
- Added send error checking in `send_tcp`
- Enabled TCP_NODELAY on all sockets
- Added socket-based tests for version mismatch and multi-fragment

**Phase 4 — VFS Correctness**
- Handle cache eviction on remove/rmdir, path update on rename
- Added missing errno→NfsStat3 mappings (EMLINK, EDQUOT, EXDEV)
- Extended setattr with atime/mtime support via utimensat
- Fixed access() to check actual file permission bits
- Added test_vfs.cpp with 9 tests

**Phase 5 — NFS Protocol Correctness**
- Implemented SETATTR guard (sattrguard3) check with NFS3ERR_NOT_SYNC
- Implemented CREATE GUARDED mode (reject duplicate with NFS3ERR_EXIST)
- Fixed FSINFO rtmult/wtmult to 4096 (was incorrectly set to 1MB)
- Fixed PATHCONF case_insensitive to false (correct for Linux)
- Fixed MKNOD to fully consume mknoddata3 args
- Added WRITE count validation against data length
- Extracted decode_sattr3() helper to deduplicate sattr3 parsing
- Added procedure-level tests

**Phase 6 — Mount & Main**
- Export path now comes from --export CLI arg (was hardcoded to "/")
- Async-signal-safe shutdown (sig_atomic_t flag + nanosleep loop)
- Registered MOUNTPROC3_UMNTALL handler
- Added port range validation

## Deferred Items
- Credential threading (passing uid/gid from RPC to VFS for proper ACCESS checks)
- READDIRPLUS with full per-entry attributes and file handles
- LRU eviction for handle cache (correctness fixed; capacity limit is separate)

## Usage

```bash
# Build and test via Docker
docker build -t nfsd-test . && docker run --rm nfsd-test

# Run a single test
docker run --rm nfsd-test ./build/tests/test_xdr --gtest_filter="XdrCodec.Uint32RoundTrip"

# Run server
docker run --rm -it --privileged -v /path/to/share:/export nfsd-test ./build/nfsd --export /export --port 2049
```
