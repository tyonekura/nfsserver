# P1 — Correctness & Stability

## Status: Complete

| # | Item | Status |
|---|------|--------|
| 1 | Lease expiry & client cleanup | Done |
| 2 | Sequence ID enforcement | Done |
| 3 | OP_COMMIT (v4) | Done |
| 4 | OP_READLINK (v4) | Done |
| 5 | OP_LINK (v4) | Done |
| 6 | WCC pre-op attributes (v3) | Done |
| 7 | READDIRPLUS attrs & handles (v3) | Done |
| 8 | READDIR cookieverf (v3/v4) | Done |

## Details

### 1. Lease expiry & client cleanup
- Added reaper thread to `Nfs4StateManager` that runs every 30s
- Expires confirmed clients whose lease exceeds `NFS4_LEASE_TIME` (90s)
- Removes all associated open state and client_id mappings
- Clean shutdown via `atomic<bool>` flag

### 2. Sequence ID enforcement
- `open_file()`: validates seqid == open_seqid + 1 for re-opens
- `confirm_open()`: validates seqid == open_seqid + 1
- `close_file()`: validates seqid == open_seqid + 1
- Returns `NFS4ERR_BAD_SEQID` on mismatch
- Added `BadSeqid` unit test

### 3. OP_COMMIT (v4)
- Added `OP_COMMIT = 5` to Nfs4Op enum
- Handler decodes stateid+offset+count, calls `vfs_.commit()`, returns write_verifier

### 4. OP_READLINK (v4)
- Added `OP_READLINK = 27` to Nfs4Op enum
- Handler calls `vfs_.readlink()` and encodes target as utf8str

### 5. OP_LINK (v4)
- Added `OP_LINK = 11` to Nfs4Op enum
- Handler: saved_fh = source file, current_fh = target dir, calls `vfs_.link()`
- Returns change_info4 for target directory

### 6. WCC pre-op attributes (v3)
- `encode_wcc_data()` now accepts optional `Fattr3* pre` parameter
- When provided, encodes wcc_attr (size, mtime, ctime) as pre_op_attr
- Updated all 10 mutating procedures: SETATTR, WRITE, CREATE, MKDIR, SYMLINK, MKNOD, REMOVE, RMDIR, RENAME, LINK, COMMIT

### 7. READDIRPLUS attrs & handles (v3)
- Each READDIRPLUS entry now includes post_op_attr (fattr3) and post_op_fh3
- Uses `vfs_.lookup()` per entry to get attrs and file handle

### 8. READDIR cookieverf (v3/v4)
- Generates verifier from directory mtime: `(mtime.sec << 32) | mtime.nsec`
- Validates on non-initial requests (cookie != 0 && client_verf != 0)
- Returns NFS3ERR_BAD_COOKIE / NFS4ERR_BAD_COOKIE on mismatch
- Applied to v3 READDIR, v3 READDIRPLUS, and v4 READDIR
