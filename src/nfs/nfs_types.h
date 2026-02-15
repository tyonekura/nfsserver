#pragma once

#include <cstdint>

// RFC 1813 §3 - NFS v3 procedure numbers
constexpr uint32_t NFSPROC3_NULL        = 0;  // RFC 1813 §3.3.0 - Procedure 0: NULL
constexpr uint32_t NFSPROC3_GETATTR     = 1;  // RFC 1813 §3.3.1 - Procedure 1: GETATTR
constexpr uint32_t NFSPROC3_SETATTR     = 2;  // RFC 1813 §3.3.2 - Procedure 2: SETATTR
constexpr uint32_t NFSPROC3_LOOKUP      = 3;  // RFC 1813 §3.3.3 - Procedure 3: LOOKUP
constexpr uint32_t NFSPROC3_ACCESS      = 4;  // RFC 1813 §3.3.4 - Procedure 4: ACCESS
constexpr uint32_t NFSPROC3_READLINK    = 5;  // RFC 1813 §3.3.5 - Procedure 5: READLINK
constexpr uint32_t NFSPROC3_READ        = 6;  // RFC 1813 §3.3.6 - Procedure 6: READ
constexpr uint32_t NFSPROC3_WRITE       = 7;  // RFC 1813 §3.3.7 - Procedure 7: WRITE
constexpr uint32_t NFSPROC3_CREATE      = 8;  // RFC 1813 §3.3.8 - Procedure 8: CREATE
constexpr uint32_t NFSPROC3_MKDIR       = 9;  // RFC 1813 §3.3.9 - Procedure 9: MKDIR
constexpr uint32_t NFSPROC3_SYMLINK     = 10; // RFC 1813 §3.3.10 - Procedure 10: SYMLINK
constexpr uint32_t NFSPROC3_MKNOD       = 11; // RFC 1813 §3.3.11 - Procedure 11: MKNOD
constexpr uint32_t NFSPROC3_REMOVE      = 12; // RFC 1813 §3.3.12 - Procedure 12: REMOVE
constexpr uint32_t NFSPROC3_RMDIR       = 13; // RFC 1813 §3.3.13 - Procedure 13: RMDIR
constexpr uint32_t NFSPROC3_RENAME      = 14; // RFC 1813 §3.3.14 - Procedure 14: RENAME
constexpr uint32_t NFSPROC3_LINK        = 15; // RFC 1813 §3.3.15 - Procedure 15: LINK
constexpr uint32_t NFSPROC3_READDIR     = 16; // RFC 1813 §3.3.16 - Procedure 16: READDIR
constexpr uint32_t NFSPROC3_READDIRPLUS = 17; // RFC 1813 §3.3.17 - Procedure 17: READDIRPLUS
constexpr uint32_t NFSPROC3_FSSTAT      = 18; // RFC 1813 §3.3.18 - Procedure 18: FSSTAT
constexpr uint32_t NFSPROC3_FSINFO      = 19; // RFC 1813 §3.3.19 - Procedure 19: FSINFO
constexpr uint32_t NFSPROC3_PATHCONF    = 20; // RFC 1813 §3.3.20 - Procedure 20: PATHCONF
constexpr uint32_t NFSPROC3_COMMIT      = 21; // RFC 1813 §3.3.21 - Procedure 21: COMMIT

// RFC 1813 §3.3.4 - ACCESS3 check bits
constexpr uint32_t ACCESS3_READ    = 0x0001;
constexpr uint32_t ACCESS3_LOOKUP  = 0x0002;
constexpr uint32_t ACCESS3_MODIFY  = 0x0004;
constexpr uint32_t ACCESS3_EXTEND  = 0x0008;
constexpr uint32_t ACCESS3_DELETE  = 0x0010;
constexpr uint32_t ACCESS3_EXECUTE = 0x0020;

// RFC 1813 §3.3.7 - stable_how
constexpr uint32_t UNSTABLE  = 0;
constexpr uint32_t DATA_SYNC = 1;
constexpr uint32_t FILE_SYNC = 2;

// RFC 1813 §3.3.8 - createmode3
constexpr uint32_t UNCHECKED = 0;
constexpr uint32_t GUARDED   = 1;
constexpr uint32_t EXCLUSIVE = 2;
