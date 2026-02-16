# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Standalone NFSv3 + NFSv4.0 server implemented from scratch in C++17 for Linux. Does not use any existing open-source NFS implementation. Implements the full protocol stack per:

- **RFC 1813** — NFS Version 3 Protocol
- **RFC 7530** — NFS Version 4.0 Protocol
- **RFC 5531** — ONC RPC v2
- **RFC 4506** — XDR (External Data Representation)

NFSv3 and NFSv4.0 run on the same TCP port (2049) alongside MOUNT v3, dispatched by the shared RPC server.

## Build & Test

All builds and tests **must** run inside Docker (Linux). The codebase uses Linux-only APIs (`MSG_NOSIGNAL`, `sys/sysmacros.h`) and will not compile on macOS.

```bash
# Build image and run all tests
docker build -t nfsd-test . && docker run --rm nfsd-test

# Run a single test
docker run --rm nfsd-test ./build/tests/test_nfs4 --gtest_filter="Nfs4Deleg.GrantReadDelegation"

# Open a shell in the container for debugging
docker run --rm -it nfsd-test bash

# Integration test (v3 + v4 mount, lock, delegation)
docker run --rm --privileged nfsd-test bash -c '
  mkdir -p /tmp/nfs_export && echo test > /tmp/nfs_export/hello.txt
  ./build/nfsd --export /tmp/nfs_export --port 2049 &
  sleep 1
  mkdir -p /mnt/nfs3 /mnt/nfs4
  mount -t nfs -o vers=3,proto=tcp,port=2049,nolock 127.0.0.1:/ /mnt/nfs3
  mount -t nfs4 -o vers=4.0,proto=tcp,port=2049 127.0.0.1:/ /mnt/nfs4
  cat /mnt/nfs3/hello.txt && cat /mnt/nfs4/hello.txt
  flock /mnt/nfs4/hello.txt cat /mnt/nfs4/hello.txt
  echo "=== All OK ==="
'
```

The `Dockerfile` uses Ubuntu 22.04, installs build-essential/cmake/git, builds the project, and defaults to running `ctest`.

## Architecture

The server is layered bottom-up:

```
main.cpp → RpcServer → {MountServer, NfsServer, Nfs4Server} → Vfs → LocalFs
```

### Layer Details

- **XDR (`src/xdr/`)** — RFC 4506 encoder/decoder. All protocol messages serialize through `XdrEncoder`/`XdrDecoder`. Data is 4-byte aligned, big-endian.

- **ONC RPC (`src/rpc/`)** — TCP server with record marking (4-byte length-prefixed fragments). Dispatches calls by program/version/procedure number. Supports AUTH_NONE and AUTH_SYS. Each client gets its own thread. Multiple programs (MOUNT, NFS v3, NFS v4) share the same port.

- **VFS (`src/vfs/`)** — Abstract `Vfs` interface with `LocalFs` passthrough implementation. File handles are 16 bytes (inode + device). Handle-to-path mapping is cached in-memory with a mutex-protected map. Includes `mknod()` for FIFO/SOCK/CHR/BLK creation.

- **MOUNT (`src/mount/`)** — MOUNT v3 protocol (program 100005). Returns root file handle for exported paths.

- **NFS v3 (`src/nfs/`)** — All 22 NFSv3 procedures. `nfs_server.cpp` has dispatch + helpers (fattr3 encoding, post_op_attr, wcc_data with pre-op attrs). `nfs_procedures.cpp` has the individual procedure implementations.

- **NFS v4 (`src/nfs4/`)** — NFSv4.0 COMPOUND processor with ~30 operation handlers:
  - `nfs4_server.cpp` — COMPOUND dispatch, all op handlers (OPEN, CLOSE, READ, WRITE, LOCK, DELEGRETURN, VERIFY, etc.)
  - `nfs4_state.cpp` — State manager: client tracking, open state, lock state (byte-range with conflict detection + range splitting), delegation state, lease expiry reaper thread
  - `nfs4_attrs.cpp` — fattr4 encode/decode, bitmap helpers, owner@domain mapping
  - `nfs4_callback.cpp` — Outbound callback channel: universal address parsing, CB_NULL probe, CB_RECALL for delegation recall
  - `nfs4_types.h` — All NFSv4 constants, opcodes, status codes, stateid struct

### Key Design Decisions

- MOUNT, NFS v3, and NFS v4 share the same RPC server on port 2049 (no portmapper/rpcbind needed).
- File handles encode raw inode + device numbers. The handle-to-path cache (`handle_to_path_`) is the critical state — stale handles return NFS3ERR_STALE / NFS4ERR_STALE.
- `MSG_NOSIGNAL` is used for TCP sends — this is Linux-only.
- NFSv4 state (clients, opens, locks, delegations) is managed in-memory by `Nfs4StateManager` with a single mutex. Linear search on vectors for state lookup.
- Delegation recall uses NFS4ERR_DELAY: on conflicting open, the server sends CB_RECALL to the delegating client and returns NFS4ERR_DELAY to the requesting client, which retries after DELEGRETURN arrives.
- Callback channel opens a fresh TCP connection per recall (simple, adequate for dev server).

## NFSv4 Feature Status

### Completed (P1 + P2 + P3 partial)
- Client state: SETCLIENTID/CONFIRM with callback info storage, lease expiry + reaper
- Open/close: OPEN (all create modes including EXCLUSIVE4), OPEN_CONFIRM, OPEN_DOWNGRADE, CLOSE
- File ops: READ, WRITE, COMMIT, GETATTR, SETATTR, ACCESS, LOOKUP, LOOKUPP, READDIR, READLINK, LINK, CREATE, REMOVE, RENAME
- Filehandle ops: PUTFH, PUTROOTFH, GETFH, SAVEFH, RESTOREFH
- Byte-range locking: LOCK, LOCKT, LOCKU, RELEASE_LOCKOWNER (conflict detection, range splitting, seqid validation)
- Delegations: Read + write delegation granting, CB_RECALL via callback channel, DELEGRETURN, DELEGPURGE
- Conditional ops: VERIFY, NVERIFY
- Other: RENEW, owner@domain encoding, UTF-8 validation, credential threading
- Claim types: CLAIM_NULL, CLAIM_DELEGATE_CUR; CLAIM_PREVIOUS/CLAIM_DELEGATE_PREV return NFS4ERR_NO_GRACE

### Not Yet Implemented
- Grace period / CLAIM_PREVIOUS, OP_SECINFO, ACLs, RPCSEC_GSS, OP_OPENATTR, NLM
- See `docs/remaining-work.md` for full list with effort estimates

## Testing

Unit tests use GoogleTest (fetched via CMake FetchContent). 5 test suites, 35+ tests:
- `tests/test_xdr.cpp` — XDR round-trip encoding
- `tests/test_rpc.cpp` — AUTH_SYS parsing, constants
- `tests/test_nfs.cpp` — File handle comparison, NFS constants
- `tests/test_vfs.cpp` — VFS operations
- `tests/test_nfs4.cpp` — Attribute codec, state management, seqid validation, byte-range locking (10 tests), delegations (9 tests), callback address parsing (3 tests)

Integration testing: mount from a Linux client with:
- v3: `mount -t nfs -o vers=3,proto=tcp,port=2049,nolock <host>:/ /mnt/nfs3`
- v4: `mount -t nfs4 -o vers=4.0,proto=tcp,port=2049 <host>:/ /mnt/nfs4`

## Progress Tracking

- `progress/p1-correctness.md` — P1 items #1-8 (all done)
- `progress/p2-interoperability.md` — P2 items #9-15 (all done)
- `progress/p3-completeness.md` — P3 items #16-31 (#16-19 done, rest pending)
- `docs/remaining-work.md` — Full remaining work with effort estimates

## Workflow

- **Always commit after each task.** When a task is completed, stage and commit the changes before moving on.
- **Build and test in Docker.** All compilation and testing happens inside the Docker container.
- **Follow established patterns.** New op handlers follow the same `OpHandler` signature. State structs go in `nfs4_state.h`. New RPC programs register via `rpc.register_program()`.
