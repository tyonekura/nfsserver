# Remaining Work: NFSv3 & NFSv4.0

Estimated effort for all remaining features, organized by priority tier.

**Effort scale:** S (< 1 hr), M (2-4 hrs), L (4-8 hrs), XL (1-2 days), XXL (3+ days)

---

## Priority 1 — Correctness & Stability

These fix protocol violations or reliability issues that can cause data loss, client confusion, or resource leaks.

| # | Item | Protocol | Effort | Description |
|---|------|----------|--------|-------------|
| 1 | Lease expiry & client cleanup | v4 | M | State manager tracks `last_renewed` but never expires clients or evicts open state. Add a timer thread that removes expired clients (>90s) and their open state. Without this, server leaks memory on every client that disconnects without CLOSE. |
| 2 | Sequence ID enforcement | v4 | M | OPEN/CLOSE/OPEN_CONFIRM accept any seqid. Should validate seqid == expected and return NFS4ERR_BAD_SEQID on mismatch, or detect retransmits (seqid == last). RFC 7530 §8.1.5. |
| 3 | OP_COMMIT | v4 | S | Missing entirely. VFS already has `fsync()` (used by v3 COMMIT). Just wire it up: decode stateid+offset+count, call fsync, return write_verifier. |
| 4 | OP_READLINK | v4 | S | VFS has `readlink()` but no v4 handler. Add handler: read current_fh symlink target, encode as utf8str. |
| 5 | OP_LINK (hard links) | v4 | S | VFS has `link()`. Add handler: saved_fh = source file, current_fh = target dir, decode newname, call link, return change_info4. |
| 6 | WCC pre-op attributes | v3 | M | All mutating v3 procedures return empty pre-op attrs. Should call getattr before the operation, save size+mtime+ctime, then encode as wcc_attr. Touches ~10 procedures. |
| 7 | READDIRPLUS attrs & handles | v3 | M | Currently returns entries without attributes or file handles. Should stat each entry and encode post_op_attr + post_op_fh3. May need a per-entry getattr + lookup in VFS. |
| 8 | READDIR cookieverf | v3/v4 | S | Cookie verifier is ignored in both versions. Generate a verifier from directory mtime; return NFS3ERR_BAD_COOKIE / NFS4ERR_BAD_COOKIE if directory changed between calls. |

**Subtotal: ~3-4 days**

---

## Priority 2 — Interoperability

Features that real-world clients expect or that cause warnings/failures with common Linux/macOS NFS clients.

| # | Item | Protocol | Effort | Description |
|---|------|----------|--------|-------------|
| 9 | owner/owner_group as user@domain | v4 | L | Currently encodes uid/gid as numeric strings ("1000"). RFC 7530 requires "user@domain" format. Add a configurable domain, passwd/group lookup (getpwuid/getgrgid), and fallback to numeric. Decode path: parse "user@domain" → uid. |
| 10 | OP_OPEN_DOWNGRADE | v4 | M | Clients expect to downgrade READ+WRITE to READ without full close/reopen. Add handler that modifies share access/deny in open state and bumps stateid.seqid. |
| 11 | OP_VERIFY / OP_NVERIFY | v4 | M | Conditional attribute check operations. VERIFY: decode bitmap+attrs, compare against current attrs, return NFS4_OK if match or NFS4ERR_NOT_SAME. NVERIFY: inverse. Used by clients for cache validation. |
| 12 | Credential threading to VFS | v3/v4 | L | AUTH_SYS uid/gid is parsed but ignored. Pass credentials down to VFS ops, use seteuid/setegid (or fchownat-style checks) for permission enforcement. Affects all procedures. Security-critical. |
| 13 | OPEN EXCLUSIVE4 create mode | v4 | M | Verifier-based exclusive create is parsed but not enforced. Should check if file exists with matching verifier (stored in timestamps or xattr), return existing handle if match, NFS4ERR_EXIST if not. |
| 14 | UTF-8 validation | v4 | S | No UTF-8 validation on filenames. Add a check on all decoded strings; return NFS4ERR_INVAL on invalid UTF-8 sequences. |
| 15 | MKNOD implementation | v3 | M | Returns NFS3ERR_NOTSUPP. Implement for FIFO and SOCK using `mkfifo()` / `mknod()`. Block/char devices can remain NOTSUPP for safety. |

**Subtotal: ~4-5 days**

---

## Priority 3 — Completeness

Features required for full RFC compliance but rarely needed for basic file serving.

| # | Item | Protocol | Effort | Description |
|---|------|----------|--------|-------------|
| 16 | Byte-range locking (LOCK/LOCKT/LOCKU) | v4 | XL | Full file locking subsystem: lock state per-file, conflict detection, lock owner tracking, RELEASE_LOCKOWNER. Need lock_owner → stateid mapping, deadlock avoidance. Most complex missing feature. |
| 17 | Read delegations | v4 | XL | Allow server to delegate read access. Track delegation state, issue CB_RECALL when conflicts arise. Requires callback channel (server→client RPC). Major performance benefit but large implementation. |
| 18 | Write delegations | v4 | XXL | More complex than read delegations. Must handle conflict resolution, data flushing on recall. Depends on callback channel + read delegation infrastructure. |
| 19 | Callback channel | v4 | XL | Server→client RPC for delegation recall (CB_RECALL, CB_GETATTR). Client provides callback info during SETCLIENTID. Server must connect to client's callback port. Required for any delegation support. |
| 20 | Grace period / CLAIM_PREVIOUS | v4 | L | After server restart, enter grace period (~90s) during which only reclaim operations (CLAIM_PREVIOUS) are allowed. Requires persistent state or at minimum a timer. |
| 21 | OP_SECINFO | v4 | M | Return available security mechanisms for a given path. Currently only AUTH_SYS. Return a list of {AUTH_SYS} until Kerberos is added. |
| 22 | ACL support (NFSv4) | v4 | XL | ~~Done — mode-based ACL synthesis. GETATTR returns OWNER@/GROUP@/EVERYONE@ ALLOW ACEs from mode bits; SETATTR maps ACL back to chmod. ACLSUPPORT reports ALLOW_ACL.~~ |
| 23 | RPCSEC_GSS / Kerberos | v3/v4 | XXL | Full GSS-API integration. Requires krb5 libraries, GSSAPI context establishment, integrity/privacy wrapping of RPC messages. Most complex auth feature. |
| 24 | OP_OPENATTR (named attributes) | v4 | L | Open the named attribute directory for a file. Map to filesystem xattrs. Need to present xattrs as a virtual directory with READDIR/LOOKUP/READ/WRITE. |
| 25 | UDP transport | v3 | L | Add UDP listener to RPC server alongside TCP. Handle per-datagram RPC (no record marking). Retransmit detection via XID cache. |
| 26 | Portmapper / rpcbind | v3 | M | Register NFS/MOUNT programs with rpcbind (port 111). Allows clients to discover services without specifying port. Implement as a simple RPC client that calls PMAP_SET. |
| 27 | FS_LOCATIONS attribute | v4 | M | Encode filesystem location referrals. Allows clients to follow server-indicated migration/replication paths. Useful for multi-server setups. |
| 28 | Quota attributes | v4 | M | QUOTA_AVAIL_HARD/SOFT/USED. Query filesystem quotas via `quotactl()` and encode in fattr4. |
| 29 | ACLSUPPORT attribute | v4 | S | Report which ACL features are available. Even without full ACL support, should report 0 (no ACL support) rather than omitting the attribute entirely. |
| 30 | NLM4 — Network Lock Manager | v3 | XL | Advisory byte-range locking for NFSv3 clients (program 100021, version 4). Currently clients must use `mount -o nolock`. Requires: NLM XDR types, NlmStateManager (conflict detection, range splitting — reuse algorithms from NFSv4 lock engine), synchronous procedures (NULL/TEST/LOCK/CANCEL/UNLOCK), async MSG variants with NLM4_GRANTED callback, blocking-lock wait queue with background granter thread, FREE_ALL for crash cleanup, cross-protocol conflict detection with NFSv4 locks. RPC dispatch already supports multiple programs on same port. Without NSM: ~3-4 days. |
| 31 | NSM integration for NLM | v3 | XL | Network Status Monitor client (program 100024) for NLM crash recovery. Register with local rpc.statd via NSM_MON, handle SM_NOTIFY callbacks when clients reboot, release all held locks for crashed clients. Requires portmapper (#26) as prerequisite. Can be deferred — NLM works without NSM but loses lock recovery on client crash. ~1-2 days. |
| 39 | NFSACL (NFSv3 ACL) | v3 | L | Sideband RPC program 100227 for NFSv3 ACL support (GETACL/SETACL procedures). Not part of RFC 1813 — separate protocol. Without this, clients must use `mount -o noacl`. Could reuse mode-based ACL synthesis from NFSv4 (#22) or implement full POSIX ACL passthrough via libacl. |

**Subtotal: ~5-7 weeks**

---

## Priority 4 — Production Hardening

Not protocol features, but needed for real-world deployment.

| # | Item | Protocol | Effort | Description |
|---|------|----------|--------|-------------|
| 32 | Connection pooling / async I/O | both | XL | Replace thread-per-client with epoll/io_uring event loop. Current model doesn't scale beyond ~100 clients. |
| 33 | Handle cache bounds | both | M | Handle-to-path cache grows unbounded. Add LRU eviction with configurable max size. |
| 34 | Multiple exports | both | M | Currently single export path. Support multiple exports with per-export config (path, allowed hosts, access mode). |
| 35 | Configuration file | both | M | Replace CLI args with config file (YAML/TOML). Export paths, port, log level, domain, lease time. |
| 36 | Logging framework | both | M | Replace cerr/cout with structured logging (syslog or file-based). Log levels, per-subsystem control. |
| 37 | Write stability enforcement | v3/v4 | M | UNSTABLE/DATA_SYNC/FILE_SYNC modes are echoed back but all writes are synchronous. Implement async writes with DATA_SYNC (fdatasync) and FILE_SYNC (fsync) distinction. |
| 38 | macOS / BSD portability | both | L | Replace Linux-only APIs (MSG_NOSIGNAL, utimensat, AT_SYMLINK_NOFOLLOW) with portable alternatives. |

**Subtotal: ~2-3 weeks**

---

## Summary by Effort

| Priority | Items | Total Effort |
|----------|-------|-------------|
| P1 — Correctness | 8 items | ~3-4 days |
| P2 — Interoperability | 7 items | ~4-5 days |
| P3 — Completeness | 17 items | ~5-7 weeks |
| P4 — Production | 7 items | ~2-3 weeks |
| **Total** | **39 items** | **~9-13 weeks** |

## Recommended Execution Order

**Week 1:** P1 items #1-5 (lease expiry, seqid, COMMIT, READLINK, LINK) — fix the most impactful correctness issues.

**Week 2:** P1 items #6-8 + P2 items #9-10 (WCC data, READDIRPLUS, cookieverf, owner@domain, OPEN_DOWNGRADE) — improve interop with real clients.

**Week 3:** P2 items #11-15 (VERIFY/NVERIFY, credential threading, EXCLUSIVE create, UTF-8, MKNOD) — complete interoperability layer.

**Weeks 4-8:** P3 items by dependency order: locking (#16) → callback channel (#19) → read delegations (#17) → write delegations (#18). Grace period (#20) and SECINFO (#21) can be done in parallel. NLM (#30) can run in parallel with v4 delegation work — it reuses range/conflict algorithms from #16 but is otherwise independent. NSM (#31) depends on portmapper (#26).

**Weeks 9+:** P4 production hardening as needed for deployment target.
