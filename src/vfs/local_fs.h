#pragma once

#include "vfs/vfs.h"
#include <map>
#include <mutex>
#include <string>

// Local filesystem passthrough VFS implementation.
// File handles encode the inode + device to uniquely identify files.
class LocalFs : public Vfs {
public:
    explicit LocalFs(const std::string& export_root);

    NfsStat3 getattr(const FileHandle& fh, Fattr3& attr) override;
    NfsStat3 setattr(const FileHandle& fh, uint32_t mode, uint32_t uid,
                      uint32_t gid, uint64_t size) override;
    NfsStat3 lookup(const FileHandle& dir_fh, const std::string& name,
                     FileHandle& out_fh, Fattr3& out_attr) override;
    NfsStat3 access(const FileHandle& fh, uint32_t requested,
                     uint32_t& granted) override;
    NfsStat3 read(const FileHandle& fh, uint64_t offset, uint32_t count,
                   std::vector<uint8_t>& data, bool& eof) override;
    NfsStat3 write(const FileHandle& fh, uint64_t offset,
                    const uint8_t* data, uint32_t count,
                    uint32_t& written) override;
    NfsStat3 create(const FileHandle& dir_fh, const std::string& name,
                     uint32_t mode, FileHandle& out_fh, Fattr3& out_attr) override;
    NfsStat3 mkdir(const FileHandle& dir_fh, const std::string& name,
                    uint32_t mode, FileHandle& out_fh, Fattr3& out_attr) override;
    NfsStat3 remove(const FileHandle& dir_fh, const std::string& name) override;
    NfsStat3 rmdir(const FileHandle& dir_fh, const std::string& name) override;
    NfsStat3 rename(const FileHandle& from_dir, const std::string& from_name,
                     const FileHandle& to_dir, const std::string& to_name) override;
    NfsStat3 readdir(const FileHandle& dir_fh, uint64_t cookie,
                      uint32_t count, std::vector<DirEntry>& entries,
                      bool& eof) override;
    NfsStat3 readlink(const FileHandle& fh, std::string& target) override;
    NfsStat3 symlink(const FileHandle& dir_fh, const std::string& name,
                      const std::string& target, FileHandle& out_fh,
                      Fattr3& out_attr) override;
    NfsStat3 link(const FileHandle& fh, const FileHandle& dir_fh,
                   const std::string& name) override;
    NfsStat3 fsstat(const FileHandle& fh, uint64_t& total_bytes,
                     uint64_t& free_bytes, uint64_t& avail_bytes,
                     uint64_t& total_files, uint64_t& free_files,
                     uint64_t& avail_files) override;
    NfsStat3 fsinfo(const FileHandle& fh, uint32_t& rtmax, uint32_t& rtpref,
                     uint32_t& wtmax, uint32_t& wtpref, uint32_t& dtpref,
                     uint64_t& maxfilesize) override;
    NfsStat3 pathconf(const FileHandle& fh, uint32_t& linkmax,
                       uint32_t& name_max) override;
    NfsStat3 commit(const FileHandle& fh, uint64_t offset,
                     uint32_t count) override;
    NfsStat3 get_root_fh(const std::string& path, FileHandle& fh) override;

private:
    // Map inode -> path for handle resolution.
    FileHandle make_handle(ino_t inode, dev_t dev);
    std::string resolve_path(const FileHandle& fh);
    void cache_path(const FileHandle& fh, const std::string& path);
    Fattr3 stat_to_fattr(const struct stat& st);
    NfsStat3 errno_to_nfsstat();

    std::string export_root_;
    std::mutex mu_;
    std::map<FileHandle, std::string> handle_to_path_;
};
