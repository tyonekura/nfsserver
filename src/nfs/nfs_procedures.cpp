#include "nfs/nfs_server.h"
#include "nfs/nfs_types.h"
#include <cstring>

void NfsServer::proc_null(const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {
    // No-op.
}

void NfsServer::proc_getattr(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    Fattr3 attr;
    NfsStat3 status = vfs_.getattr(fh, attr);
    reply.encode_uint32(static_cast<uint32_t>(status));
    if (status == NfsStat3::NFS3_OK) {
        encode_fattr3(reply, attr);
    }
}

void NfsServer::proc_setattr(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);

    // Decode sattr3: each field has a "set_it" bool.
    uint32_t mode = UINT32_MAX, uid = UINT32_MAX, gid = UINT32_MAX;
    uint64_t size = UINT64_MAX;

    if (args.decode_bool()) mode = args.decode_uint32();
    if (args.decode_bool()) uid = args.decode_uint32();
    if (args.decode_bool()) gid = args.decode_uint32();
    if (args.decode_bool()) size = args.decode_uint64();
    // atime
    NfsTimeSet atime;
    atime.how = static_cast<NfsTimeSet::How>(args.decode_uint32());
    if (atime.how == NfsTimeSet::How::SET_TO_CLIENT_TIME) {
        atime.time.seconds = args.decode_uint32();
        atime.time.nseconds = args.decode_uint32();
    }
    // mtime
    NfsTimeSet mtime;
    mtime.how = static_cast<NfsTimeSet::How>(args.decode_uint32());
    if (mtime.how == NfsTimeSet::How::SET_TO_CLIENT_TIME) {
        mtime.time.seconds = args.decode_uint32();
        mtime.time.nseconds = args.decode_uint32();
    }
    // guard (sattrguard3)
    if (args.decode_bool()) { args.decode_uint32(); args.decode_uint32(); }

    NfsStat3 status = vfs_.setattr(fh, mode, uid, gid, size, atime, mtime);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, fh);
}

void NfsServer::proc_lookup(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();

    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 status = vfs_.lookup(dir_fh, name, out_fh, out_attr);
    reply.encode_uint32(static_cast<uint32_t>(status));
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_opaque(out_fh.data, out_fh.len);
        // post_op_attr for object
        reply.encode_bool(true);
        encode_fattr3(reply, out_attr);
    }
    // post_op_attr for directory
    encode_post_op_attr(reply, dir_fh);
}

void NfsServer::proc_access(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    uint32_t requested = args.decode_uint32();

    uint32_t granted = 0;
    NfsStat3 status = vfs_.access(fh, requested, granted);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint32(granted);
    }
}

void NfsServer::proc_readlink(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    std::string target;
    NfsStat3 status = vfs_.readlink(fh, target);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_string(target);
    }
}

void NfsServer::proc_read(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    uint64_t offset = args.decode_uint64();
    uint32_t count = args.decode_uint32();

    std::vector<uint8_t> data;
    bool eof = false;
    NfsStat3 status = vfs_.read(fh, offset, count, data, eof);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint32(static_cast<uint32_t>(data.size())); // count
        reply.encode_bool(eof);
        reply.encode_opaque(data.data(), data.size());
    }
}

void NfsServer::proc_write(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    uint64_t offset = args.decode_uint64();
    uint32_t count = args.decode_uint32();
    uint32_t stable = args.decode_uint32();
    auto data = args.decode_opaque();

    uint32_t written = 0;
    NfsStat3 status = vfs_.write(fh, offset, data.data(), count, written);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint32(written);
        reply.encode_uint32(stable); // echo back requested stability
        // write verifier
        reply.encode_uint64(write_verifier_);
    }
}

void NfsServer::proc_create(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();
    uint32_t createmode = args.decode_uint32();

    uint32_t mode = 0644;
    if (createmode != EXCLUSIVE) {
        // Decode sattr3 (simplified: just get mode if set)
        if (args.decode_bool()) mode = args.decode_uint32();
        // Skip uid, gid, size, atime, mtime
        if (args.decode_bool()) args.decode_uint32(); // uid
        if (args.decode_bool()) args.decode_uint32(); // gid
        if (args.decode_bool()) args.decode_uint64(); // size
        uint32_t at = args.decode_uint32(); if (at == 2) { args.decode_uint32(); args.decode_uint32(); }
        uint32_t mt = args.decode_uint32(); if (mt == 2) { args.decode_uint32(); args.decode_uint32(); }
    } else {
        // createverf3: 8 bytes
        args.decode_uint64();
    }

    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 status = vfs_.create(dir_fh, name, mode, out_fh, out_attr);
    reply.encode_uint32(static_cast<uint32_t>(status));
    if (status == NfsStat3::NFS3_OK) {
        // post_op_fh3: true + handle
        reply.encode_bool(true);
        reply.encode_opaque(out_fh.data, out_fh.len);
        // post_op_attr
        reply.encode_bool(true);
        encode_fattr3(reply, out_attr);
    }
    encode_wcc_data(reply, dir_fh);
}

void NfsServer::proc_mkdir(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();

    uint32_t mode = 0755;
    if (args.decode_bool()) mode = args.decode_uint32();
    // Skip remaining sattr3 fields
    if (args.decode_bool()) args.decode_uint32(); // uid
    if (args.decode_bool()) args.decode_uint32(); // gid
    if (args.decode_bool()) args.decode_uint64(); // size
    uint32_t at = args.decode_uint32(); if (at == 2) { args.decode_uint32(); args.decode_uint32(); }
    uint32_t mt = args.decode_uint32(); if (mt == 2) { args.decode_uint32(); args.decode_uint32(); }

    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 status = vfs_.mkdir(dir_fh, name, mode, out_fh, out_attr);
    reply.encode_uint32(static_cast<uint32_t>(status));
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_bool(true);
        reply.encode_opaque(out_fh.data, out_fh.len);
        reply.encode_bool(true);
        encode_fattr3(reply, out_attr);
    }
    encode_wcc_data(reply, dir_fh);
}

void NfsServer::proc_symlink(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();
    // sattr3 (skip)
    if (args.decode_bool()) args.decode_uint32(); // mode
    if (args.decode_bool()) args.decode_uint32(); // uid
    if (args.decode_bool()) args.decode_uint32(); // gid
    if (args.decode_bool()) args.decode_uint64(); // size
    uint32_t at = args.decode_uint32(); if (at == 2) { args.decode_uint32(); args.decode_uint32(); }
    uint32_t mt = args.decode_uint32(); if (mt == 2) { args.decode_uint32(); args.decode_uint32(); }
    std::string target = args.decode_string();

    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 status = vfs_.symlink(dir_fh, name, target, out_fh, out_attr);
    reply.encode_uint32(static_cast<uint32_t>(status));
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_bool(true);
        reply.encode_opaque(out_fh.data, out_fh.len);
        reply.encode_bool(true);
        encode_fattr3(reply, out_attr);
    }
    encode_wcc_data(reply, dir_fh);
}

void NfsServer::proc_mknod(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();
    // Not fully implemented - return NOTSUPP
    reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_NOTSUPP));
    encode_wcc_data(reply, dir_fh);
}

void NfsServer::proc_remove(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();
    NfsStat3 status = vfs_.remove(dir_fh, name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, dir_fh);
}

void NfsServer::proc_rmdir(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();
    NfsStat3 status = vfs_.rmdir(dir_fh, name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, dir_fh);
}

void NfsServer::proc_rename(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle from_dir = decode_fh(args);
    std::string from_name = args.decode_string();
    FileHandle to_dir = decode_fh(args);
    std::string to_name = args.decode_string();

    NfsStat3 status = vfs_.rename(from_dir, from_name, to_dir, to_name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, from_dir);
    encode_wcc_data(reply, to_dir);
}

void NfsServer::proc_link(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();

    NfsStat3 status = vfs_.link(fh, dir_fh, name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    encode_wcc_data(reply, dir_fh);
}

void NfsServer::proc_readdir(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    uint64_t cookie = args.decode_uint64();
    args.decode_uint64(); // cookieverf (ignored for simplicity)
    uint32_t dircount = args.decode_uint32();

    std::vector<DirEntry> entries;
    bool eof = false;
    NfsStat3 status = vfs_.readdir(dir_fh, cookie, std::min(dircount, 128u), entries, eof);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, dir_fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint64(0); // cookieverf
        for (const auto& e : entries) {
            reply.encode_bool(true); // value follows
            reply.encode_uint64(e.fileid);
            reply.encode_string(e.name);
            reply.encode_uint64(e.cookie);
        }
        reply.encode_bool(false); // no more entries
        reply.encode_bool(eof);
    }
}

void NfsServer::proc_readdirplus(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    uint64_t cookie = args.decode_uint64();
    args.decode_uint64(); // cookieverf
    uint32_t dircount = args.decode_uint32();
    args.decode_uint32(); // maxcount (unused in simplified implementation)

    std::vector<DirEntry> entries;
    bool eof = false;
    NfsStat3 status = vfs_.readdir(dir_fh, cookie, std::min(dircount, 128u), entries, eof);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, dir_fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint64(0); // cookieverf
        for (const auto& e : entries) {
            reply.encode_bool(true); // value follows
            reply.encode_uint64(e.fileid);
            reply.encode_string(e.name);
            reply.encode_uint64(e.cookie);
            // name_attributes (post_op_attr): try to get attrs
            // For simplicity, encode false (no attributes)
            reply.encode_bool(false);
            // name_handle (post_op_fh3): false
            reply.encode_bool(false);
        }
        reply.encode_bool(false); // no more entries
        reply.encode_bool(eof);
    }
}

void NfsServer::proc_fsstat(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);

    uint64_t tbytes, fbytes, abytes, tfiles, ffiles, afiles;
    NfsStat3 status = vfs_.fsstat(fh, tbytes, fbytes, abytes, tfiles, ffiles, afiles);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint64(tbytes);
        reply.encode_uint64(fbytes);
        reply.encode_uint64(abytes);
        reply.encode_uint64(tfiles);
        reply.encode_uint64(ffiles);
        reply.encode_uint64(afiles);
        reply.encode_uint32(0); // invarsec
    }
}

void NfsServer::proc_fsinfo(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);

    uint32_t rtmax, rtpref, wtmax, wtpref, dtpref;
    uint64_t maxfilesize;
    NfsStat3 status = vfs_.fsinfo(fh, rtmax, rtpref, wtmax, wtpref, dtpref, maxfilesize);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint32(rtmax);
        reply.encode_uint32(rtpref);
        reply.encode_uint32(rtmax);   // rtmult
        reply.encode_uint32(wtmax);
        reply.encode_uint32(wtpref);
        reply.encode_uint32(wtmax);   // wtmult
        reply.encode_uint32(dtpref);
        reply.encode_uint64(maxfilesize);
        // time_delta
        reply.encode_uint32(1);  // seconds
        reply.encode_uint32(0);  // nseconds
        // properties bitmask: FSF3_LINK | FSF3_SYMLINK | FSF3_HOMOGENEOUS | FSF3_CANSETTIME
        reply.encode_uint32(0x001B);
    }
}

void NfsServer::proc_pathconf(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);

    uint32_t linkmax, name_max;
    NfsStat3 status = vfs_.pathconf(fh, linkmax, name_max);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint32(linkmax);
        reply.encode_uint32(name_max);
        reply.encode_bool(true);  // no_trunc
        reply.encode_bool(true);  // chown_restricted
        reply.encode_bool(true);  // case_insensitive (false on Linux, true for simplicity)
        reply.encode_bool(true);  // case_preserving
    }
}

void NfsServer::proc_commit(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    uint64_t offset = args.decode_uint64();
    uint32_t count = args.decode_uint32();

    NfsStat3 status = vfs_.commit(fh, offset, count);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint64(write_verifier_);
    }
}
