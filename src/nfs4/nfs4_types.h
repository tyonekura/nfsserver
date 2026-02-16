#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include "vfs/vfs.h"

// RFC 7530 - NFS Version 4 Protocol

constexpr uint32_t NFS_V4 = 4;

// RFC 7530 §16 - NFSv4 has only 2 RPC procedures
constexpr uint32_t NFSPROC4_NULL     = 0;
constexpr uint32_t NFSPROC4_COMPOUND = 1;

// RFC 7530 §16.2 - COMPOUND operation opcodes
enum class Nfs4Op : uint32_t {
    OP_ACCESS              = 3,
    OP_CLOSE               = 4,
    OP_COMMIT              = 5,
    OP_CREATE              = 6,
    OP_DELEGPURGE          = 7,
    OP_DELEGRETURN         = 8,
    OP_GETATTR             = 9,
    OP_GETFH               = 10,
    OP_LINK                = 11,
    OP_LOCK                = 12,
    OP_LOCKT               = 13,
    OP_LOCKU               = 14,
    OP_LOOKUP              = 15,
    OP_LOOKUPP             = 16,
    OP_NVERIFY             = 17,
    OP_OPEN                = 18,
    OP_OPEN_CONFIRM        = 20,
    OP_OPEN_DOWNGRADE      = 21,
    OP_PUTFH               = 22,
    OP_PUTROOTFH           = 24,
    OP_READ                = 25,
    OP_READDIR             = 26,
    OP_READLINK            = 27,
    OP_REMOVE              = 28,
    OP_RENAME              = 29,
    OP_RENEW               = 30,
    OP_RESTOREFH           = 31,
    OP_SAVEFH              = 32,
    OP_SETATTR             = 34,
    OP_SETCLIENTID         = 35,
    OP_SETCLIENTID_CONFIRM = 36,
    OP_VERIFY              = 37,
    OP_WRITE               = 38,
    OP_RELEASE_LOCKOWNER   = 39,
    OP_ILLEGAL             = 10044,
};

// RFC 7530 §13 - NFS4 status codes
enum class Nfs4Stat : uint32_t {
    NFS4_OK                    = 0,
    NFS4ERR_PERM               = 1,
    NFS4ERR_NOENT              = 2,
    NFS4ERR_IO                 = 5,
    NFS4ERR_NXIO               = 6,
    NFS4ERR_ACCESS             = 13,
    NFS4ERR_EXIST              = 17,
    NFS4ERR_XDEV               = 18,
    NFS4ERR_NOTDIR             = 20,
    NFS4ERR_ISDIR              = 21,
    NFS4ERR_INVAL              = 22,
    NFS4ERR_FBIG               = 27,
    NFS4ERR_NOSPC              = 28,
    NFS4ERR_ROFS               = 30,
    NFS4ERR_MLINK              = 31,
    NFS4ERR_NAMETOOLONG        = 63,
    NFS4ERR_NOTEMPTY           = 66,
    NFS4ERR_DQUOT              = 69,
    NFS4ERR_STALE              = 70,
    NFS4ERR_BADHANDLE          = 10001,
    NFS4ERR_BAD_COOKIE         = 10003,
    NFS4ERR_NOTSUPP            = 10004,
    NFS4ERR_TOOSMALL           = 10005,
    NFS4ERR_SERVERFAULT        = 10006,
    NFS4ERR_BADTYPE            = 10007,
    NFS4ERR_EXPIRED            = 10011,
    NFS4ERR_STALE_CLIENTID     = 10012,
    NFS4ERR_GRACE              = 10013,
    NFS4ERR_FHEXPIRED          = 10014,
    NFS4ERR_WRONGSEC           = 10016,
    NFS4ERR_MINOR_VERS_MISMATCH = 10021,
    NFS4ERR_STALE_STATEID      = 10023,
    NFS4ERR_OLD_STATEID        = 10024,
    NFS4ERR_BAD_STATEID        = 10025,
    NFS4ERR_BAD_SEQID          = 10026,
    NFS4ERR_NOT_SAME           = 10027,
    NFS4ERR_RESOURCE           = 10018,
    NFS4ERR_NOFILEHANDLE       = 10020,
    NFS4ERR_SAME               = 10009,
    NFS4ERR_DENIED             = 10010,
    NFS4ERR_LOCK_RANGE         = 10028,
    NFS4ERR_LOCKS_HELD         = 10037,
    NFS4ERR_DELAY              = 10008,
    NFS4ERR_NO_GRACE           = 10033,
    NFS4ERR_OP_ILLEGAL         = 10044,
};

// RFC 7530 §5.8.1.2 - nfs_ftype4
enum class Nfs4Type : uint32_t {
    NF4REG      = 1,
    NF4DIR      = 2,
    NF4BLK      = 3,
    NF4CHR      = 4,
    NF4LNK      = 5,
    NF4SOCK     = 6,
    NF4FIFO     = 7,
    NF4ATTRDIR  = 8,
    NF4NAMEDATTR = 9,
};

// RFC 7531 - Attribute bit positions (per RFC 7530 §5.8)
// Word 0 (bits 0-31)
constexpr uint32_t FATTR4_SUPPORTED_ATTRS  = 0;
constexpr uint32_t FATTR4_TYPE             = 1;
constexpr uint32_t FATTR4_FH_EXPIRE_TYPE   = 2;
constexpr uint32_t FATTR4_CHANGE           = 3;
constexpr uint32_t FATTR4_SIZE             = 4;
constexpr uint32_t FATTR4_LINK_SUPPORT     = 5;
constexpr uint32_t FATTR4_SYMLINK_SUPPORT  = 6;
constexpr uint32_t FATTR4_NAMED_ATTR       = 7;
constexpr uint32_t FATTR4_FSID             = 8;
constexpr uint32_t FATTR4_UNIQUE_HANDLES   = 9;
constexpr uint32_t FATTR4_LEASE_TIME       = 10;
constexpr uint32_t FATTR4_RDATTR_ERROR     = 11;
constexpr uint32_t FATTR4_ACL              = 12;
constexpr uint32_t FATTR4_ACLSUPPORT       = 13;
constexpr uint32_t FATTR4_ARCHIVE          = 14;
constexpr uint32_t FATTR4_CANSETTIME       = 15;
constexpr uint32_t FATTR4_CASE_INSENSITIVE = 16;
constexpr uint32_t FATTR4_CASE_PRESERVING  = 17;
constexpr uint32_t FATTR4_CHOWN_RESTRICTED = 18;
constexpr uint32_t FATTR4_FILEHANDLE       = 19;
constexpr uint32_t FATTR4_FILEID           = 20;
constexpr uint32_t FATTR4_FILES_AVAIL      = 21;
constexpr uint32_t FATTR4_FILES_FREE       = 22;
constexpr uint32_t FATTR4_FILES_TOTAL      = 23;
constexpr uint32_t FATTR4_FS_LOCATIONS     = 24;
constexpr uint32_t FATTR4_HIDDEN           = 25;
constexpr uint32_t FATTR4_HOMOGENEOUS      = 26;
constexpr uint32_t FATTR4_MAXFILESIZE      = 27;
constexpr uint32_t FATTR4_MAXLINK          = 28;
constexpr uint32_t FATTR4_MAXNAME          = 29;
constexpr uint32_t FATTR4_MAXREAD          = 30;
constexpr uint32_t FATTR4_MAXWRITE         = 31;
// Word 1 (bits 32-63)
constexpr uint32_t FATTR4_MIMETYPE         = 32;
constexpr uint32_t FATTR4_MODE             = 33;
constexpr uint32_t FATTR4_NO_TRUNC         = 34;
constexpr uint32_t FATTR4_NUMLINKS         = 35;
constexpr uint32_t FATTR4_OWNER            = 36;
constexpr uint32_t FATTR4_OWNER_GROUP      = 37;
constexpr uint32_t FATTR4_QUOTA_AVAIL_HARD = 38;
constexpr uint32_t FATTR4_QUOTA_AVAIL_SOFT = 39;
constexpr uint32_t FATTR4_QUOTA_USED       = 40;
constexpr uint32_t FATTR4_RAWDEV           = 41;
constexpr uint32_t FATTR4_SPACE_AVAIL      = 42;
constexpr uint32_t FATTR4_SPACE_FREE       = 43;
constexpr uint32_t FATTR4_SPACE_TOTAL      = 44;
constexpr uint32_t FATTR4_SPACE_USED       = 45;
constexpr uint32_t FATTR4_SYSTEM           = 46;
constexpr uint32_t FATTR4_TIME_ACCESS      = 47;
constexpr uint32_t FATTR4_TIME_ACCESS_SET  = 48;
constexpr uint32_t FATTR4_TIME_BACKUP      = 49;
constexpr uint32_t FATTR4_TIME_CREATE      = 50;
constexpr uint32_t FATTR4_TIME_DELTA       = 51;
constexpr uint32_t FATTR4_TIME_METADATA    = 52;
constexpr uint32_t FATTR4_TIME_MODIFY      = 53;
constexpr uint32_t FATTR4_TIME_MODIFY_SET  = 54;
constexpr uint32_t FATTR4_MOUNTED_ON_FILEID = 55;

// RFC 7530 §16.16 - OPEN share access/deny modes
constexpr uint32_t OPEN4_SHARE_ACCESS_READ  = 1;
constexpr uint32_t OPEN4_SHARE_ACCESS_WRITE = 2;
constexpr uint32_t OPEN4_SHARE_ACCESS_BOTH  = 3;
constexpr uint32_t OPEN4_SHARE_DENY_NONE    = 0;

// RFC 7530 §16.16 - open type
constexpr uint32_t OPEN4_NOCREATE = 0;
constexpr uint32_t OPEN4_CREATE   = 1;

// RFC 7530 §16.16 - create mode
constexpr uint32_t UNCHECKED4 = 0;
constexpr uint32_t GUARDED4   = 1;
constexpr uint32_t EXCLUSIVE4 = 2;

// RFC 7530 §16.16 - open claim type
constexpr uint32_t CLAIM_NULL          = 0;
constexpr uint32_t CLAIM_PREVIOUS      = 1;
constexpr uint32_t CLAIM_DELEGATE_CUR  = 2;
constexpr uint32_t CLAIM_DELEGATE_PREV = 3;

// RFC 7530 §16.16 - open result flags
constexpr uint32_t OPEN4_RESULT_CONFIRM = 0x00000002;

// RFC 7530 §16.16 - delegation type
constexpr uint32_t OPEN_DELEGATE_NONE  = 0;
constexpr uint32_t OPEN_DELEGATE_READ  = 1;
constexpr uint32_t OPEN_DELEGATE_WRITE = 2;

// RFC 7530 §16.16 - create type (for CREATE op)
constexpr uint32_t NF4_CREATE_LNK  = 5;  // symlink

// RFC 7530 §16.10 - lock types
constexpr uint32_t READ_LT   = 1;
constexpr uint32_t WRITE_LT  = 2;
constexpr uint32_t READW_LT  = 3;
constexpr uint32_t WRITEW_LT = 4;

// RFC 7530 §16.32 - stable_how4
constexpr uint32_t UNSTABLE4  = 0;
constexpr uint32_t DATA_SYNC4 = 1;
constexpr uint32_t FILE_SYNC4 = 2;

// FH expire type
constexpr uint32_t FH4_PERSISTENT = 0;

// RFC 7530 §15.3 - Callback program
constexpr uint32_t NFS4_CALLBACK = 0x40000000;
constexpr uint32_t CB_NULL = 0;
constexpr uint32_t CB_COMPOUND = 1;
constexpr uint32_t OP_CB_RECALL = 4;

// RFC 7530 §16.16 - write delegation space limit
constexpr uint32_t NFS_LIMIT_SIZE = 1;

// Lease time in seconds
constexpr uint32_t NFS4_LEASE_TIME = 90;

// RFC 7530 §3.2 - stateid4
struct Nfs4StateId {
    uint32_t seqid = 0;
    uint8_t other[12] = {};

    bool operator==(const Nfs4StateId& o) const {
        return seqid == o.seqid && std::memcmp(other, o.other, 12) == 0;
    }
};

// Convert NfsStat3 (used by VFS) to Nfs4Stat
inline Nfs4Stat nfs3stat_to_nfs4stat(NfsStat3 s) {
    // Most status codes are numerically identical between v3 and v4
    switch (s) {
        case NfsStat3::NFS3_OK:             return Nfs4Stat::NFS4_OK;
        case NfsStat3::NFS3ERR_PERM:        return Nfs4Stat::NFS4ERR_PERM;
        case NfsStat3::NFS3ERR_NOENT:       return Nfs4Stat::NFS4ERR_NOENT;
        case NfsStat3::NFS3ERR_IO:          return Nfs4Stat::NFS4ERR_IO;
        case NfsStat3::NFS3ERR_NXIO:        return Nfs4Stat::NFS4ERR_NXIO;
        case NfsStat3::NFS3ERR_ACCES:       return Nfs4Stat::NFS4ERR_ACCESS;
        case NfsStat3::NFS3ERR_EXIST:       return Nfs4Stat::NFS4ERR_EXIST;
        case NfsStat3::NFS3ERR_XDEV:        return Nfs4Stat::NFS4ERR_XDEV;
        case NfsStat3::NFS3ERR_NODEV:       return Nfs4Stat::NFS4ERR_INVAL;
        case NfsStat3::NFS3ERR_NOTDIR:      return Nfs4Stat::NFS4ERR_NOTDIR;
        case NfsStat3::NFS3ERR_ISDIR:       return Nfs4Stat::NFS4ERR_ISDIR;
        case NfsStat3::NFS3ERR_INVAL:       return Nfs4Stat::NFS4ERR_INVAL;
        case NfsStat3::NFS3ERR_FBIG:        return Nfs4Stat::NFS4ERR_FBIG;
        case NfsStat3::NFS3ERR_NOSPC:       return Nfs4Stat::NFS4ERR_NOSPC;
        case NfsStat3::NFS3ERR_ROFS:        return Nfs4Stat::NFS4ERR_ROFS;
        case NfsStat3::NFS3ERR_MLINK:       return Nfs4Stat::NFS4ERR_MLINK;
        case NfsStat3::NFS3ERR_NAMETOOLONG: return Nfs4Stat::NFS4ERR_NAMETOOLONG;
        case NfsStat3::NFS3ERR_NOTEMPTY:    return Nfs4Stat::NFS4ERR_NOTEMPTY;
        case NfsStat3::NFS3ERR_DQUOT:       return Nfs4Stat::NFS4ERR_DQUOT;
        case NfsStat3::NFS3ERR_STALE:       return Nfs4Stat::NFS4ERR_STALE;
        case NfsStat3::NFS3ERR_BADHANDLE:   return Nfs4Stat::NFS4ERR_BADHANDLE;
        case NfsStat3::NFS3ERR_NOT_SYNC:    return Nfs4Stat::NFS4ERR_INVAL;
        case NfsStat3::NFS3ERR_BAD_COOKIE:  return Nfs4Stat::NFS4ERR_BAD_COOKIE;
        case NfsStat3::NFS3ERR_NOTSUPP:     return Nfs4Stat::NFS4ERR_NOTSUPP;
        case NfsStat3::NFS3ERR_TOOSMALL:    return Nfs4Stat::NFS4ERR_TOOSMALL;
        case NfsStat3::NFS3ERR_SERVERFAULT: return Nfs4Stat::NFS4ERR_SERVERFAULT;
        default:                            return Nfs4Stat::NFS4ERR_SERVERFAULT;
    }
}

// Convert Ftype3 to Nfs4Type
inline Nfs4Type ftype3_to_nfs4type(Ftype3 t) {
    switch (t) {
        case Ftype3::NF3REG:  return Nfs4Type::NF4REG;
        case Ftype3::NF3DIR:  return Nfs4Type::NF4DIR;
        case Ftype3::NF3BLK:  return Nfs4Type::NF4BLK;
        case Ftype3::NF3CHR:  return Nfs4Type::NF4CHR;
        case Ftype3::NF3LNK:  return Nfs4Type::NF4LNK;
        case Ftype3::NF3SOCK: return Nfs4Type::NF4SOCK;
        case Ftype3::NF3FIFO: return Nfs4Type::NF4FIFO;
        default:              return Nfs4Type::NF4REG;
    }
}
