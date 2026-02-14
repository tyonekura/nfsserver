#include "vfs/local_fs.h"

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

LocalFs::LocalFs(const std::string& export_root)
    : export_root_(export_root) {}

FileHandle LocalFs::make_handle(ino_t inode, dev_t dev) {
    FileHandle fh;
    // Encode inode and device into handle.
    // Use first 8 bytes for inode, next 8 for device.
    fh.len = 16;
    std::memcpy(fh.data, &inode, sizeof(inode));
    std::memcpy(fh.data + 8, &dev, sizeof(dev));
    return fh;
}

void LocalFs::cache_path(const FileHandle& fh, const std::string& path) {
    std::lock_guard<std::mutex> lock(mu_);
    handle_to_path_[fh] = path;
}

std::string LocalFs::resolve_path(const FileHandle& fh) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = handle_to_path_.find(fh);
    if (it != handle_to_path_.end())
        return it->second;
    return "";
}

NfsStat3 LocalFs::errno_to_nfsstat() {
    switch (errno) {
        case EPERM:       return NfsStat3::NFS3ERR_PERM;
        case ENOENT:      return NfsStat3::NFS3ERR_NOENT;
        case EIO:         return NfsStat3::NFS3ERR_IO;
        case ENXIO:       return NfsStat3::NFS3ERR_NXIO;
        case EACCES:      return NfsStat3::NFS3ERR_ACCES;
        case EEXIST:      return NfsStat3::NFS3ERR_EXIST;
        case ENODEV:      return NfsStat3::NFS3ERR_NODEV;
        case ENOTDIR:     return NfsStat3::NFS3ERR_NOTDIR;
        case EISDIR:      return NfsStat3::NFS3ERR_ISDIR;
        case EINVAL:      return NfsStat3::NFS3ERR_INVAL;
        case EFBIG:       return NfsStat3::NFS3ERR_FBIG;
        case ENOSPC:      return NfsStat3::NFS3ERR_NOSPC;
        case EROFS:       return NfsStat3::NFS3ERR_ROFS;
        case ENAMETOOLONG: return NfsStat3::NFS3ERR_NAMETOOLONG;
        case ENOTEMPTY:   return NfsStat3::NFS3ERR_NOTEMPTY;
        default:          return NfsStat3::NFS3ERR_IO;
    }
}

Fattr3 LocalFs::stat_to_fattr(const struct stat& st) {
    Fattr3 attr;

    if (S_ISREG(st.st_mode))       attr.type = Ftype3::NF3REG;
    else if (S_ISDIR(st.st_mode))  attr.type = Ftype3::NF3DIR;
    else if (S_ISBLK(st.st_mode))  attr.type = Ftype3::NF3BLK;
    else if (S_ISCHR(st.st_mode))  attr.type = Ftype3::NF3CHR;
    else if (S_ISLNK(st.st_mode))  attr.type = Ftype3::NF3LNK;
    else if (S_ISSOCK(st.st_mode)) attr.type = Ftype3::NF3SOCK;
    else if (S_ISFIFO(st.st_mode)) attr.type = Ftype3::NF3FIFO;

    attr.mode = st.st_mode & 07777;
    attr.nlink = st.st_nlink;
    attr.uid = st.st_uid;
    attr.gid = st.st_gid;
    attr.size = st.st_size;
    attr.used = st.st_blocks * 512;
    attr.fsid = st.st_dev;
    attr.fileid = st.st_ino;

#ifdef __linux__
    attr.atime = {static_cast<uint32_t>(st.st_atim.tv_sec),
                  static_cast<uint32_t>(st.st_atim.tv_nsec)};
    attr.mtime = {static_cast<uint32_t>(st.st_mtim.tv_sec),
                  static_cast<uint32_t>(st.st_mtim.tv_nsec)};
    attr.ctime = {static_cast<uint32_t>(st.st_ctim.tv_sec),
                  static_cast<uint32_t>(st.st_ctim.tv_nsec)};
#else
    attr.atime = {static_cast<uint32_t>(st.st_atime), 0};
    attr.mtime = {static_cast<uint32_t>(st.st_mtime), 0};
    attr.ctime = {static_cast<uint32_t>(st.st_ctime), 0};
#endif

    return attr;
}

NfsStat3 LocalFs::get_root_fh(const std::string& path, FileHandle& fh) {
    std::string full = export_root_ + path;
    struct stat st;
    if (lstat(full.c_str(), &st) != 0)
        return errno_to_nfsstat();
    fh = make_handle(st.st_ino, st.st_dev);
    cache_path(fh, full);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::getattr(const FileHandle& fh, Fattr3& attr) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) return errno_to_nfsstat();
    attr = stat_to_fattr(st);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::setattr(const FileHandle& fh, uint32_t mode, uint32_t uid,
                            uint32_t gid, uint64_t size) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;

    if (mode != UINT32_MAX)
        if (chmod(path.c_str(), mode) != 0) return errno_to_nfsstat();
    if (uid != UINT32_MAX || gid != UINT32_MAX) {
        uid_t u = (uid != UINT32_MAX) ? uid : static_cast<uid_t>(-1);
        gid_t g = (gid != UINT32_MAX) ? gid : static_cast<gid_t>(-1);
        if (chown(path.c_str(), u, g) != 0) return errno_to_nfsstat();
    }
    if (size != UINT64_MAX)
        if (truncate(path.c_str(), size) != 0) return errno_to_nfsstat();

    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::lookup(const FileHandle& dir_fh, const std::string& name,
                           FileHandle& out_fh, Fattr3& out_attr) {
    std::string dir_path = resolve_path(dir_fh);
    if (dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string full = dir_path + "/" + name;
    struct stat st;
    if (lstat(full.c_str(), &st) != 0)
        return errno_to_nfsstat();

    out_fh = make_handle(st.st_ino, st.st_dev);
    cache_path(out_fh, full);
    out_attr = stat_to_fattr(st);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::access(const FileHandle& fh, uint32_t requested,
                           uint32_t& granted) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;
    // Simplified: grant all requested access.
    granted = requested;
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::read(const FileHandle& fh, uint64_t offset, uint32_t count,
                         std::vector<uint8_t>& data, bool& eof) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return errno_to_nfsstat();

    data.resize(count);
    ssize_t n = pread(fd, data.data(), count, offset);
    close(fd);

    if (n < 0) return errno_to_nfsstat();
    data.resize(n);
    eof = (static_cast<size_t>(n) < count);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::write(const FileHandle& fh, uint64_t offset,
                          const uint8_t* wdata, uint32_t count,
                          uint32_t& written) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;

    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) return errno_to_nfsstat();

    ssize_t n = pwrite(fd, wdata, count, offset);
    close(fd);

    if (n < 0) return errno_to_nfsstat();
    written = static_cast<uint32_t>(n);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::create(const FileHandle& dir_fh, const std::string& name,
                           uint32_t mode, FileHandle& out_fh, Fattr3& out_attr) {
    std::string dir_path = resolve_path(dir_fh);
    if (dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string full = dir_path + "/" + name;
    int fd = open(full.c_str(), O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0) return errno_to_nfsstat();

    struct stat st;
    fstat(fd, &st);
    close(fd);

    out_fh = make_handle(st.st_ino, st.st_dev);
    cache_path(out_fh, full);
    out_attr = stat_to_fattr(st);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::mkdir(const FileHandle& dir_fh, const std::string& name,
                          uint32_t mode, FileHandle& out_fh, Fattr3& out_attr) {
    std::string dir_path = resolve_path(dir_fh);
    if (dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string full = dir_path + "/" + name;
    if (::mkdir(full.c_str(), mode) != 0)
        return errno_to_nfsstat();

    struct stat st;
    if (lstat(full.c_str(), &st) != 0) return errno_to_nfsstat();

    out_fh = make_handle(st.st_ino, st.st_dev);
    cache_path(out_fh, full);
    out_attr = stat_to_fattr(st);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::remove(const FileHandle& dir_fh, const std::string& name) {
    std::string dir_path = resolve_path(dir_fh);
    if (dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string full = dir_path + "/" + name;
    if (unlink(full.c_str()) != 0) return errno_to_nfsstat();
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::rmdir(const FileHandle& dir_fh, const std::string& name) {
    std::string dir_path = resolve_path(dir_fh);
    if (dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string full = dir_path + "/" + name;
    if (::rmdir(full.c_str()) != 0) return errno_to_nfsstat();
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::rename(const FileHandle& from_dir, const std::string& from_name,
                           const FileHandle& to_dir, const std::string& to_name) {
    std::string from_dir_path = resolve_path(from_dir);
    std::string to_dir_path = resolve_path(to_dir);
    if (from_dir_path.empty() || to_dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string from = from_dir_path + "/" + from_name;
    std::string to = to_dir_path + "/" + to_name;
    if (::rename(from.c_str(), to.c_str()) != 0) return errno_to_nfsstat();
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::readdir(const FileHandle& dir_fh, uint64_t cookie,
                            uint32_t count, std::vector<DirEntry>& entries,
                            bool& eof) {
    std::string dir_path = resolve_path(dir_fh);
    if (dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    DIR* dir = opendir(dir_path.c_str());
    if (!dir) return errno_to_nfsstat();

    uint64_t idx = 0;
    struct dirent* ent;
    entries.clear();

    while ((ent = ::readdir(dir)) != nullptr) {
        idx++;
        if (idx <= cookie) continue;
        if (entries.size() >= count) break;

        DirEntry de;
        de.fileid = ent->d_ino;
        de.name = ent->d_name;
        de.cookie = idx;
        entries.push_back(std::move(de));

        // Cache the path for this entry.
        std::string full = dir_path + "/" + ent->d_name;
        struct stat st;
        if (lstat(full.c_str(), &st) == 0) {
            auto fh = make_handle(st.st_ino, st.st_dev);
            cache_path(fh, full);
        }
    }

    eof = (::readdir(dir) == nullptr);
    closedir(dir);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::readlink(const FileHandle& fh, std::string& target) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;

    char buf[4096];
    ssize_t n = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
    if (n < 0) return errno_to_nfsstat();
    buf[n] = '\0';
    target = buf;
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::symlink(const FileHandle& dir_fh, const std::string& name,
                            const std::string& target, FileHandle& out_fh,
                            Fattr3& out_attr) {
    std::string dir_path = resolve_path(dir_fh);
    if (dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string full = dir_path + "/" + name;
    if (::symlink(target.c_str(), full.c_str()) != 0)
        return errno_to_nfsstat();

    struct stat st;
    if (lstat(full.c_str(), &st) != 0) return errno_to_nfsstat();
    out_fh = make_handle(st.st_ino, st.st_dev);
    cache_path(out_fh, full);
    out_attr = stat_to_fattr(st);
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::link(const FileHandle& fh, const FileHandle& dir_fh,
                         const std::string& name) {
    std::string src_path = resolve_path(fh);
    std::string dir_path = resolve_path(dir_fh);
    if (src_path.empty() || dir_path.empty()) return NfsStat3::NFS3ERR_STALE;

    std::string full = dir_path + "/" + name;
    if (::link(src_path.c_str(), full.c_str()) != 0) return errno_to_nfsstat();
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::fsstat(const FileHandle& fh, uint64_t& total_bytes,
                           uint64_t& free_bytes, uint64_t& avail_bytes,
                           uint64_t& total_files, uint64_t& free_files,
                           uint64_t& avail_files) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;

    struct statvfs sv;
    if (statvfs(path.c_str(), &sv) != 0) return errno_to_nfsstat();

    total_bytes = sv.f_blocks * sv.f_frsize;
    free_bytes = sv.f_bfree * sv.f_frsize;
    avail_bytes = sv.f_bavail * sv.f_frsize;
    total_files = sv.f_files;
    free_files = sv.f_ffree;
    avail_files = sv.f_favail;
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::fsinfo(const FileHandle& /*fh*/, uint32_t& rtmax, uint32_t& rtpref,
                           uint32_t& wtmax, uint32_t& wtpref, uint32_t& dtpref,
                           uint64_t& maxfilesize) {
    rtmax = 1048576;    // 1 MB
    rtpref = 65536;     // 64 KB
    wtmax = 1048576;
    wtpref = 65536;
    dtpref = 8192;
    maxfilesize = UINT64_MAX;
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::pathconf(const FileHandle& /*fh*/, uint32_t& linkmax,
                             uint32_t& name_max) {
    linkmax = 32000;
    name_max = 255;
    return NfsStat3::NFS3_OK;
}

NfsStat3 LocalFs::commit(const FileHandle& fh, uint64_t /*offset*/, uint32_t /*count*/) {
    std::string path = resolve_path(fh);
    if (path.empty()) return NfsStat3::NFS3ERR_STALE;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return errno_to_nfsstat();
    fsync(fd);
    close(fd);
    return NfsStat3::NFS3_OK;
}
