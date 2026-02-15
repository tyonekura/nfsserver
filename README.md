# nfsserver

A standalone NFS server implemented from scratch in C++17 for Linux, supporting both NFSv3 and NFSv4.0. No external NFS libraries — the full protocol stack is built from the ground up per the RFCs.

- **RFC 1813** — NFS Version 3 Protocol
- **RFC 7530** — NFS Version 4.0 Protocol
- **RFC 5531** — ONC RPC v2
- **RFC 4506** — XDR (External Data Representation)

## Features

- **NFSv3**: All 22 procedures implemented
- **NFSv4.0**: COMPOUND dispatch with 22 operation handlers (OPEN, READ, WRITE, CLOSE, READDIR, LOOKUP, CREATE, REMOVE, RENAME, SETATTR, etc.)
- Both versions served on a single TCP port (no portmapper needed)
- NFSv4 stateful operations: SETCLIENTID, OPEN/CLOSE with stateids, lease renewal
- NFSv4 bitmap-based attribute encoding per RFC 7530/7531
- ONC RPC with multi-fragment record reassembly
- AUTH_NONE and AUTH_SYS credential parsing
- Local filesystem passthrough via abstract VFS layer
- Thread-per-client architecture
- Handle cache with eviction on delete/rename

## Quick Start

Requires Docker.

```bash
# Build and run tests
docker build -t nfsd-test .
docker run --rm nfsd-test

# Start the server with a shared directory
docker run --rm --privileged -v /path/to/share:/export nfsd-test \
  ./build/nfsd --export /export --port 2049

# Mount from a Linux client (NFSv3)
mount -t nfs -o vers=3,proto=tcp,port=2049,mountport=2049,nolock,noacl \
  <server-ip>:/export /mnt/nfs

# Mount from a Linux client (NFSv4)
mount -t nfs4 -o vers=4.0,proto=tcp,port=2049 <server-ip>:/ /mnt/nfs
```

### Try it in a single container

```bash
# NFSv3
docker run --rm --privileged nfsd-test bash -c '
  mkdir -p /export /mnt/nfs
  echo "hello NFS" > /export/test.txt
  ./build/nfsd --export /export --port 2049 &
  sleep 1
  mount -t nfs -o vers=3,proto=tcp,port=2049,mountport=2049,nolock,noacl \
    127.0.0.1:/export /mnt/nfs
  cat /mnt/nfs/test.txt
  echo "written via NFS" > /mnt/nfs/newfile.txt
  ls -la /mnt/nfs
'

# NFSv4
docker run --rm --privileged nfsd-test bash -c '
  mkdir -p /export /mnt/nfs
  echo "hello NFS" > /export/test.txt
  ./build/nfsd --export /export --port 2049 &
  sleep 1
  mount -t nfs4 -o vers=4.0,proto=tcp,port=2049 127.0.0.1:/ /mnt/nfs
  cat /mnt/nfs/test.txt
  echo "written via NFSv4" > /mnt/nfs/newfile.txt
  ls -la /mnt/nfs
'
```

## Architecture

```
main.cpp --> RpcServer --> MountServer --> Vfs --> LocalFs
                      |--> NfsServer  --/
                      \--> Nfs4Server --/
```

| Layer | Directory | Description |
|-------|-----------|-------------|
| XDR | `src/xdr/` | RFC 4506 encoder/decoder. 4-byte aligned, big-endian. |
| ONC RPC | `src/rpc/` | TCP server with record marking. Per-client threads. |
| VFS | `src/vfs/` | Abstract filesystem interface + local passthrough. |
| MOUNT | `src/mount/` | MOUNT v3 protocol. Returns root file handle. |
| NFS v3 | `src/nfs/` | All 22 NFSv3 procedures with dispatch framework. |
| NFS v4 | `src/nfs4/` | NFSv4.0 COMPOUND dispatch, bitmap attrs, state management. |

### Key Design Decisions

- MOUNT, NFSv3, and NFSv4 share a single RPC server on one TCP port — no portmapper/rpcbind required
- NFSv4 uses PUTROOTFH + LOOKUP instead of the MOUNT protocol
- File handles are 16 bytes encoding inode + device numbers
- Handle-to-path cache is mutex-protected with eviction on delete/rename
- `MSG_NOSIGNAL` for TCP sends (Linux-only)
- TCP_NODELAY enabled for low-latency request-response
- Async-signal-safe shutdown via `sig_atomic_t` flag

## Building Without Docker

Requires Linux, CMake 3.16+, and a C++17 compiler.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
sudo ./build/nfsd --export /path/to/share --port 2049
```

## Tests

5 test suites using GoogleTest:

| Suite | Coverage |
|-------|----------|
| `test_xdr` | All XDR types, alignment, padding, underflow |
| `test_rpc` | AUTH_SYS parsing, version mismatch reply, multi-fragment reassembly |
| `test_vfs` | File operations, cache eviction, permissions, timestamps |
| `test_nfs` | NFS procedure encoding, SETATTR guard, CREATE GUARDED, FSINFO/PATHCONF |
| `test_nfs4` | Bitmap codec, attribute encoding, state management, COMPOUND dispatch |

```bash
# Run all tests
docker run --rm nfsd-test

# Run a specific test
docker run --rm nfsd-test ./build/tests/test_xdr --gtest_filter="XdrCodec.Uint32RoundTrip"
```

## Limitations

### NFSv3
- **No NLM** — file locking not implemented (use `nolock` mount option)
- **No ACL support** — use `noacl` mount option
- **MKNOD** — returns NFS3ERR_NOTSUPP
- **READDIRPLUS** — returns entries without per-entry attributes/handles
- **EXCLUSIVE create** — verifier consumed but idempotent retry not fully implemented

### NFSv4
- **Minor version 0 only** — NFSv4.1/4.2 not supported
- **No delegations** — OPEN always returns OPEN_DELEGATE_NONE
- **No ACL support** — ACL attribute not implemented
- **No KERBEROS** — AUTH_SYS only, owner/group encoded as numeric strings
- **No lease expiry enforcement** — leases tracked but not evicted on timeout

### General
- **No portmapper** — all protocols share a single TCP port
- **No credential threading** — access checks use file permission bits, not per-user uid/gid

## License

This project is provided as-is for educational and research purposes.
