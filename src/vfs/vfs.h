#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <sys/stat.h>

// RFC 1813 §2.3.3 - nfs_fh3: opaque file handle (max 64 bytes)
constexpr size_t NFS3_FHSIZE = 64;

struct FileHandle {
    uint8_t data[NFS3_FHSIZE] = {};
    size_t len = 0;

    bool operator==(const FileHandle& o) const;
    bool operator<(const FileHandle& o) const;
};

// RFC 1813 §2.6 - nfsstat3: NFS status codes
enum class NfsStat3 : uint32_t {
    NFS3_OK             = 0,
    NFS3ERR_PERM        = 1,
    NFS3ERR_NOENT       = 2,
    NFS3ERR_IO          = 5,
    NFS3ERR_NXIO        = 6,
    NFS3ERR_ACCES       = 13,
    NFS3ERR_EXIST       = 17,
    NFS3ERR_XDEV        = 18,
    NFS3ERR_NODEV       = 19,
    NFS3ERR_NOTDIR      = 20,
    NFS3ERR_ISDIR       = 21,
    NFS3ERR_INVAL       = 22,
    NFS3ERR_FBIG        = 27,
    NFS3ERR_NOSPC       = 28,
    NFS3ERR_ROFS        = 30,
    NFS3ERR_MLINK       = 31,
    NFS3ERR_NAMETOOLONG = 63,
    NFS3ERR_NOTEMPTY    = 66,
    NFS3ERR_DQUOT       = 69,
    NFS3ERR_STALE       = 70,
    NFS3ERR_BADHANDLE   = 10001,
    NFS3ERR_NOT_SYNC    = 10002,
    NFS3ERR_BAD_COOKIE  = 10003,
    NFS3ERR_NOTSUPP     = 10004,
    NFS3ERR_TOOSMALL    = 10005,
    NFS3ERR_SERVERFAULT = 10006,
};

// RFC 1813 §2.2 - ftype3: file types
enum class Ftype3 : uint32_t {
    NF3REG  = 1,
    NF3DIR  = 2,
    NF3BLK  = 3,
    NF3CHR  = 4,
    NF3LNK  = 5,
    NF3SOCK = 6,
    NF3FIFO = 7,
};

// RFC 1813 §2.5 - nfstime3
struct NfsTime3 {
    uint32_t seconds = 0;
    uint32_t nseconds = 0;
};

// RFC 1813 §2.5 - fattr3: file attributes
struct Fattr3 {
    Ftype3 type = Ftype3::NF3REG;
    uint32_t mode = 0;
    uint32_t nlink = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint64_t size = 0;
    uint64_t used = 0;
    uint32_t rdev_major = 0;
    uint32_t rdev_minor = 0;
    uint64_t fsid = 0;
    uint64_t fileid = 0;  // inode number
    NfsTime3 atime;
    NfsTime3 mtime;
    NfsTime3 ctime;
};

// RFC 1813 §2.5 - set_atime / set_mtime (part of sattr3)
struct NfsTimeSet {
    enum class How : uint32_t {
        DONT_CHANGE = 0,
        SET_TO_SERVER_TIME = 1,
        SET_TO_CLIENT_TIME = 2
    } how = How::DONT_CHANGE;
    NfsTime3 time;
};

// RFC 1813 §3.3.16 - entry3 (READDIR entry)
struct DirEntry {
    uint64_t fileid;
    std::string name;
    uint64_t cookie;
};

// Abstract VFS interface.
class Vfs {
public:
    virtual ~Vfs() = default;

    virtual NfsStat3 getattr(const FileHandle& fh, Fattr3& attr) = 0;
    virtual NfsStat3 setattr(const FileHandle& fh, uint32_t mode, uint32_t uid,
                              uint32_t gid, uint64_t size,
                              NfsTimeSet atime, NfsTimeSet mtime) = 0;
    virtual NfsStat3 lookup(const FileHandle& dir_fh, const std::string& name,
                             FileHandle& out_fh, Fattr3& out_attr) = 0;
    virtual NfsStat3 access(const FileHandle& fh, uint32_t requested,
                             uint32_t& granted) = 0;
    virtual NfsStat3 read(const FileHandle& fh, uint64_t offset, uint32_t count,
                           std::vector<uint8_t>& data, bool& eof) = 0;
    virtual NfsStat3 write(const FileHandle& fh, uint64_t offset,
                            const uint8_t* data, uint32_t count,
                            uint32_t& written) = 0;
    virtual NfsStat3 create(const FileHandle& dir_fh, const std::string& name,
                             uint32_t mode, FileHandle& out_fh, Fattr3& out_attr) = 0;
    virtual NfsStat3 mkdir(const FileHandle& dir_fh, const std::string& name,
                            uint32_t mode, FileHandle& out_fh, Fattr3& out_attr) = 0;
    virtual NfsStat3 remove(const FileHandle& dir_fh, const std::string& name) = 0;
    virtual NfsStat3 rmdir(const FileHandle& dir_fh, const std::string& name) = 0;
    virtual NfsStat3 rename(const FileHandle& from_dir, const std::string& from_name,
                             const FileHandle& to_dir, const std::string& to_name) = 0;
    virtual NfsStat3 readdir(const FileHandle& dir_fh, uint64_t cookie,
                              uint32_t count, std::vector<DirEntry>& entries,
                              bool& eof) = 0;
    virtual NfsStat3 readlink(const FileHandle& fh, std::string& target) = 0;
    virtual NfsStat3 symlink(const FileHandle& dir_fh, const std::string& name,
                              const std::string& target, FileHandle& out_fh,
                              Fattr3& out_attr) = 0;
    virtual NfsStat3 link(const FileHandle& fh, const FileHandle& dir_fh,
                           const std::string& name) = 0;
    virtual NfsStat3 fsstat(const FileHandle& fh, uint64_t& total_bytes,
                             uint64_t& free_bytes, uint64_t& avail_bytes,
                             uint64_t& total_files, uint64_t& free_files,
                             uint64_t& avail_files) = 0;
    virtual NfsStat3 fsinfo(const FileHandle& fh, uint32_t& rtmax, uint32_t& rtpref,
                             uint32_t& wtmax, uint32_t& wtpref, uint32_t& dtpref,
                             uint64_t& maxfilesize) = 0;
    virtual NfsStat3 pathconf(const FileHandle& fh, uint32_t& linkmax,
                               uint32_t& name_max) = 0;
    virtual NfsStat3 commit(const FileHandle& fh, uint64_t offset,
                             uint32_t count) = 0;
    virtual NfsStat3 mknod(const FileHandle& dir_fh, const std::string& name,
                            Ftype3 type, uint32_t mode,
                            uint32_t rdev_major, uint32_t rdev_minor,
                            FileHandle& out_fh, Fattr3& out_attr) = 0;

    // Get file handle for export root path.
    virtual NfsStat3 get_root_fh(const std::string& path, FileHandle& fh) = 0;
};
