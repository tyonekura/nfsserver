#pragma once

#include "rpc/rpc_server.h"
#include "vfs/vfs.h"

class NfsServer {
public:
    explicit NfsServer(Vfs& vfs);

    RpcProgramHandlers get_handlers();

private:
    FileHandle decode_fh(XdrDecoder& dec);                          // RFC 1813 §2.3.3 - nfs_fh3
    void encode_fattr3(XdrEncoder& enc, const Fattr3& attr);        // RFC 1813 §2.5 - fattr3
    void encode_post_op_attr(XdrEncoder& enc, const FileHandle& fh); // RFC 1813 §2.6 - post_op_attr
    void encode_wcc_data(XdrEncoder& enc, const FileHandle& fh,
                          const Fattr3* pre = nullptr);              // RFC 1813 §2.6 - wcc_data

public:
    // RFC 1813 §2.5 - sattr3 (settable file attributes)
    struct Sattr3 {
        uint32_t mode = UINT32_MAX;
        uint32_t uid = UINT32_MAX;
        uint32_t gid = UINT32_MAX;
        uint64_t size = UINT64_MAX;
        NfsTimeSet atime;
        NfsTimeSet mtime;
    };
    static Sattr3 decode_sattr3(XdrDecoder& args);

private:

    // Procedure implementations.
    void proc_null(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_getattr(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_setattr(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_lookup(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_access(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_readlink(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_read(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_write(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_create(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_mkdir(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_symlink(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_mknod(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_remove(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_rmdir(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_rename(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_link(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_readdir(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_readdirplus(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_fsstat(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_fsinfo(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_pathconf(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_commit(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);

    Vfs& vfs_;
    uint64_t write_verifier_ = 0; // server boot time, used for COMMIT
};
