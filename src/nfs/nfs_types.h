#pragma once

#include <cstdint>

// NFS v3 procedure numbers per RFC 1813
constexpr uint32_t NFSPROC3_NULL        = 0;
constexpr uint32_t NFSPROC3_GETATTR     = 1;
constexpr uint32_t NFSPROC3_SETATTR     = 2;
constexpr uint32_t NFSPROC3_LOOKUP      = 3;
constexpr uint32_t NFSPROC3_ACCESS      = 4;
constexpr uint32_t NFSPROC3_READLINK    = 5;
constexpr uint32_t NFSPROC3_READ        = 6;
constexpr uint32_t NFSPROC3_WRITE       = 7;
constexpr uint32_t NFSPROC3_CREATE      = 8;
constexpr uint32_t NFSPROC3_MKDIR       = 9;
constexpr uint32_t NFSPROC3_SYMLINK     = 10;
constexpr uint32_t NFSPROC3_MKNOD       = 11;
constexpr uint32_t NFSPROC3_REMOVE      = 12;
constexpr uint32_t NFSPROC3_RMDIR       = 13;
constexpr uint32_t NFSPROC3_RENAME      = 14;
constexpr uint32_t NFSPROC3_LINK        = 15;
constexpr uint32_t NFSPROC3_READDIR     = 16;
constexpr uint32_t NFSPROC3_READDIRPLUS = 17;
constexpr uint32_t NFSPROC3_FSSTAT      = 18;
constexpr uint32_t NFSPROC3_FSINFO      = 19;
constexpr uint32_t NFSPROC3_PATHCONF    = 20;
constexpr uint32_t NFSPROC3_COMMIT      = 21;

// ACCESS3 check bits
constexpr uint32_t ACCESS3_READ    = 0x0001;
constexpr uint32_t ACCESS3_LOOKUP  = 0x0002;
constexpr uint32_t ACCESS3_MODIFY  = 0x0004;
constexpr uint32_t ACCESS3_EXTEND  = 0x0008;
constexpr uint32_t ACCESS3_DELETE  = 0x0010;
constexpr uint32_t ACCESS3_EXECUTE = 0x0020;

// Write stable_how
constexpr uint32_t UNSTABLE  = 0;
constexpr uint32_t DATA_SYNC = 1;
constexpr uint32_t FILE_SYNC = 2;

// createmode3
constexpr uint32_t UNCHECKED = 0;
constexpr uint32_t GUARDED   = 1;
constexpr uint32_t EXCLUSIVE = 2;
