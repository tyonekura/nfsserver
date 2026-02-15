#include "nfs/nfs_server.h"
#include "nfs/nfs_types.h"
#include <chrono>

NfsServer::NfsServer(Vfs& vfs) : vfs_(vfs) {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    write_verifier_ = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
}

RpcProgramHandlers NfsServer::get_handlers() {
    RpcProgramHandlers h;
    auto bind = [this](auto fn) {
        return [this, fn](const RpcCallHeader& c, XdrDecoder& a, XdrEncoder& r) {
            (this->*fn)(c, a, r);
        };
    };

    h.procedures[NFSPROC3_NULL]        = bind(&NfsServer::proc_null);
    h.procedures[NFSPROC3_GETATTR]     = bind(&NfsServer::proc_getattr);
    h.procedures[NFSPROC3_SETATTR]     = bind(&NfsServer::proc_setattr);
    h.procedures[NFSPROC3_LOOKUP]      = bind(&NfsServer::proc_lookup);
    h.procedures[NFSPROC3_ACCESS]      = bind(&NfsServer::proc_access);
    h.procedures[NFSPROC3_READLINK]    = bind(&NfsServer::proc_readlink);
    h.procedures[NFSPROC3_READ]        = bind(&NfsServer::proc_read);
    h.procedures[NFSPROC3_WRITE]       = bind(&NfsServer::proc_write);
    h.procedures[NFSPROC3_CREATE]      = bind(&NfsServer::proc_create);
    h.procedures[NFSPROC3_MKDIR]       = bind(&NfsServer::proc_mkdir);
    h.procedures[NFSPROC3_SYMLINK]     = bind(&NfsServer::proc_symlink);
    h.procedures[NFSPROC3_MKNOD]       = bind(&NfsServer::proc_mknod);
    h.procedures[NFSPROC3_REMOVE]      = bind(&NfsServer::proc_remove);
    h.procedures[NFSPROC3_RMDIR]       = bind(&NfsServer::proc_rmdir);
    h.procedures[NFSPROC3_RENAME]      = bind(&NfsServer::proc_rename);
    h.procedures[NFSPROC3_LINK]        = bind(&NfsServer::proc_link);
    h.procedures[NFSPROC3_READDIR]     = bind(&NfsServer::proc_readdir);
    h.procedures[NFSPROC3_READDIRPLUS] = bind(&NfsServer::proc_readdirplus);
    h.procedures[NFSPROC3_FSSTAT]      = bind(&NfsServer::proc_fsstat);
    h.procedures[NFSPROC3_FSINFO]      = bind(&NfsServer::proc_fsinfo);
    h.procedures[NFSPROC3_PATHCONF]    = bind(&NfsServer::proc_pathconf);
    h.procedures[NFSPROC3_COMMIT]      = bind(&NfsServer::proc_commit);

    return h;
}

// RFC 1813 §2.3.3 - Decode nfs_fh3 (variable-length opaque file handle)
FileHandle NfsServer::decode_fh(XdrDecoder& dec) {
    auto opaque = dec.decode_opaque();
    FileHandle fh;
    fh.len = std::min(opaque.size(), sizeof(fh.data));
    std::memcpy(fh.data, opaque.data(), fh.len);
    return fh;
}

// RFC 1813 §2.5 - Encode fattr3 (file attributes)
void NfsServer::encode_fattr3(XdrEncoder& enc, const Fattr3& attr) {
    enc.encode_uint32(static_cast<uint32_t>(attr.type));
    enc.encode_uint32(attr.mode);
    enc.encode_uint32(attr.nlink);
    enc.encode_uint32(attr.uid);
    enc.encode_uint32(attr.gid);
    enc.encode_uint64(attr.size);
    enc.encode_uint64(attr.used);
    // rdev: specdata3 (two uint32)
    enc.encode_uint32(attr.rdev_major);
    enc.encode_uint32(attr.rdev_minor);
    enc.encode_uint64(attr.fsid);
    enc.encode_uint64(attr.fileid);
    enc.encode_uint32(attr.atime.seconds);
    enc.encode_uint32(attr.atime.nseconds);
    enc.encode_uint32(attr.mtime.seconds);
    enc.encode_uint32(attr.mtime.nseconds);
    enc.encode_uint32(attr.ctime.seconds);
    enc.encode_uint32(attr.ctime.nseconds);
}

// RFC 1813 §2.6 - post_op_attr (optional fattr3)
void NfsServer::encode_post_op_attr(XdrEncoder& enc, const FileHandle& fh) {
    Fattr3 attr;
    if (vfs_.getattr(fh, attr) == NfsStat3::NFS3_OK) {
        enc.encode_bool(true);
        encode_fattr3(enc, attr);
    } else {
        enc.encode_bool(false);
    }
}

// RFC 1813 §2.6 - wcc_data (weak cache consistency: pre_op_attr + post_op_attr)
void NfsServer::encode_wcc_data(XdrEncoder& enc, const FileHandle& fh,
                                 const Fattr3* pre) {
    if (pre) {
        // pre_op_attr: wcc_attr (size, mtime, ctime)
        enc.encode_bool(true);
        enc.encode_uint64(pre->size);
        enc.encode_uint32(pre->mtime.seconds);
        enc.encode_uint32(pre->mtime.nseconds);
        enc.encode_uint32(pre->ctime.seconds);
        enc.encode_uint32(pre->ctime.nseconds);
    } else {
        enc.encode_bool(false);
    }
    encode_post_op_attr(enc, fh);
}
