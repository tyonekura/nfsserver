# P3 #22: ACL Support — Design Options

## Context

NFSv4 defines an ACL attribute (FATTR4_ACL, bit 12) that carries a list of Access Control Entries (ACEs). Each ACE has `{type, flag, access_mask, who}`. Clients query ACLs via GETATTR and set them via SETATTR. A companion attribute FATTR4_ACLSUPPORT (bit 13) tells clients what ACL features the server supports.

Currently our server reports neither attribute — both are commented out as "not supported" in `src/nfs4/nfs4_attrs.cpp`.

## Current Architecture (relevant files)

| File | Role |
|------|------|
| `src/nfs4/nfs4_attrs.h` | `Nfs4SetAttr` struct, bitmap helpers, `encode_fattr4()` / `decode_fattr4_setattr()` declarations |
| `src/nfs4/nfs4_attrs.cpp` | Attribute encode/decode — bits 12-13 are stubs at lines 189-190 |
| `src/nfs4/nfs4_types.h` | `FATTR4_ACL=12`, `FATTR4_ACLSUPPORT=13` already defined; no ACE structs |
| `src/nfs4/nfs4_server.cpp` | GETATTR/SETATTR handlers; delegation ACEs encoded with raw magic numbers (lines 679-694) |
| `src/vfs/vfs.h` | Abstract VFS — no ACL methods |
| `src/vfs/local_fs.cpp` | POSIX file ops only — no `acl_*` or `getxattr` calls |

## Option A: Mode-Based ACL Synthesis (Recommended)

Synthesize NFSv4 ACLs from POSIX mode bits. This is what most lightweight NFS servers do (including the Linux kernel NFS server when no actual ACLs are stored).

### How it works

**GETATTR (ACL):** Convert the file's `mode` into 3-6 NFSv4 ACEs:
- `ALLOW OWNER@ {read/write/execute based on owner bits}`
- `ALLOW GROUP@ {based on group bits}`
- `ALLOW EVERYONE@ {based on other bits}`

**SETATTR (ACL):** Parse the ACE list, extract permissions for OWNER@/GROUP@/EVERYONE@, map back to a `chmod()` call.

**ACLSUPPORT:** Report `ACL4_SUPPORT_ALLOW_ACL` (0x1) — we support ALLOW ACEs only.

### Pros
- No new dependencies (no libacl)
- Simple, predictable — ACLs always reflect mode bits
- Clients like `nfs4_getfacl` / `nfs4_setfacl` work
- Covers P3 #22 and #29 together

### Cons
- No per-user/group ACEs beyond owner/group/other
- DENY ACEs not supported
- Lossy — setting complex ACLs reduces to chmod

### Effort: M (medium)

---

## Option B: POSIX ACL Passthrough

Use Linux POSIX ACL APIs (`<sys/acl.h>`, libacl) to read/write real per-user/group ACLs on the underlying filesystem.

### How it works

**GETATTR (ACL):** Call `acl_get_file()`, translate POSIX ACL entries to NFSv4 ACEs.

**SETATTR (ACL):** Translate NFSv4 ACEs back to POSIX ACL entries, call `acl_set_file()`.

**ACLSUPPORT:** Report `ACL4_SUPPORT_ALLOW_ACL | ACL4_SUPPORT_DENY_ACL` (0x3).

### Pros
- Real per-user/group ACL support
- ACLs persist across server restarts
- More complete RFC 7530 compliance

### Cons
- Requires `libacl` dependency (`apt install libacl1-dev`, link `-lacl`)
- POSIX ACL ↔ NFSv4 ACL translation is complex and lossy (different models)
- DENY ACE mapping to POSIX is imperfect
- Filesystem must support POSIX ACLs (ext4/xfs do, some don't)

### Effort: XL (extra large)

---

## Option C: Minimal (ACLSUPPORT=0 only)

Just report that ACLs are not supported. Clients will not attempt ACL operations.

### How it works

**GETATTR (ACLSUPPORT):** Return `0` (no ACL types supported).

**GETATTR (ACL):** Not advertised in supported bitmap — clients won't request it.

**SETATTR (ACL):** Return `NFS4ERR_ATTRNOTSUPP` if attempted.

### Pros
- Trivial implementation (~10 lines)
- No risk of bugs
- Covers P3 #29

### Cons
- Does NOT actually implement ACL support (P3 #22 stays incomplete)
- `nfs4_getfacl` returns nothing useful

### Effort: S (small) — but only covers #29, not #22
