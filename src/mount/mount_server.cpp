#include "mount/mount_server.h"
#include "mount/mount_types.h"

MountServer::MountServer(Vfs& vfs, const std::vector<std::string>& exports)
    : vfs_(vfs), exports_(exports) {}

RpcProgramHandlers MountServer::get_handlers() {
    RpcProgramHandlers h;
    h.procedures[MOUNTPROC3_NULL] = [this](auto& c, auto& a, auto& r) { proc_null(c, a, r); };
    h.procedures[MOUNTPROC3_MNT] = [this](auto& c, auto& a, auto& r) { proc_mnt(c, a, r); };
    h.procedures[MOUNTPROC3_DUMP] = [this](auto& c, auto& a, auto& r) { proc_dump(c, a, r); };
    h.procedures[MOUNTPROC3_UMNT] = [this](auto& c, auto& a, auto& r) { proc_umnt(c, a, r); };
    h.procedures[MOUNTPROC3_UMNTALL] = [this](auto& c, auto& a, auto& r) { proc_umntall(c, a, r); };
    h.procedures[MOUNTPROC3_EXPORT] = [this](auto& c, auto& a, auto& r) { proc_export(c, a, r); };
    return h;
}

// RFC 1813 §A.5.1 - MOUNTPROC3_NULL: Do nothing
void MountServer::proc_null(const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {
    // No-op.
}

// RFC 1813 §A.5.2 - MOUNTPROC3_MNT: Add mount entry, return file handle
void MountServer::proc_mnt(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    std::string dirpath = args.decode_string();

    // Check if the path is in our export list, also accept "/" as alias
    bool found = false;
    for (const auto& exp : exports_) {
        if (dirpath == exp || dirpath == "/") { found = true; break; }
    }

    if (!found) {
        reply.encode_uint32(static_cast<uint32_t>(MountStat3::MNT3ERR_ACCES));
        return;
    }

    FileHandle fh;
    NfsStat3 stat = vfs_.get_root_fh("/", fh);
    if (stat != NfsStat3::NFS3_OK) {
        reply.encode_uint32(static_cast<uint32_t>(MountStat3::MNT3ERR_NOENT));
        return;
    }

    reply.encode_uint32(static_cast<uint32_t>(MountStat3::MNT3_OK));
    // File handle as variable-length opaque
    reply.encode_opaque(fh.data, fh.len);
    // Auth flavors: just AUTH_SYS
    reply.encode_uint32(1); // count
    reply.encode_uint32(static_cast<uint32_t>(RpcAuthFlavor::AUTH_SYS));
}

// RFC 1813 §A.5.3 - MOUNTPROC3_DUMP: Return list of mount entries
void MountServer::proc_dump(const RpcCallHeader&, XdrDecoder&, XdrEncoder& reply) {
    // Return empty mount list (no entry = FALSE discriminant).
    reply.encode_bool(false);
}

// RFC 1813 §A.5.4 - MOUNTPROC3_UMNT: Remove mount entry
void MountServer::proc_umnt(const RpcCallHeader&, XdrDecoder& args, XdrEncoder&) {
    // Just consume the dirpath argument; we don't track mount state.
    args.decode_string();
}

// RFC 1813 §A.5.5 - MOUNTPROC3_UMNTALL: Remove all mount entries
void MountServer::proc_umntall(const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {
    // No-op: we don't track per-client mount state.
}

// RFC 1813 §A.5.6 - MOUNTPROC3_EXPORT: Return export list
void MountServer::proc_export(const RpcCallHeader&, XdrDecoder&, XdrEncoder& reply) {
    for (const auto& exp : exports_) {
        reply.encode_bool(true);  // follows
        reply.encode_string(exp);
        // Groups list: empty (anyone can mount)
        reply.encode_bool(false);
    }
    reply.encode_bool(false);  // end of export list
}
