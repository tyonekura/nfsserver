#include "nfs/nfs_server.h"
#include "nfs/nfs_types.h"
#include <cstring>

// RFC 1813 §2.5 - Decode sattr3 (settable file attributes)
NfsServer::Sattr3 NfsServer::decode_sattr3(XdrDecoder& args) {
    Sattr3 sa;
    if (args.decode_bool()) sa.mode = args.decode_uint32();
    if (args.decode_bool()) sa.uid = args.decode_uint32();
    if (args.decode_bool()) sa.gid = args.decode_uint32();
    if (args.decode_bool()) sa.size = args.decode_uint64();
    sa.atime.how = static_cast<NfsTimeSet::How>(args.decode_uint32());
    if (sa.atime.how == NfsTimeSet::How::SET_TO_CLIENT_TIME) {
        sa.atime.time.seconds = args.decode_uint32();
        sa.atime.time.nseconds = args.decode_uint32();
    }
    sa.mtime.how = static_cast<NfsTimeSet::How>(args.decode_uint32());
    if (sa.mtime.how == NfsTimeSet::How::SET_TO_CLIENT_TIME) {
        sa.mtime.time.seconds = args.decode_uint32();
        sa.mtime.time.nseconds = args.decode_uint32();
    }
    return sa;
}

// RFC 1813 §3.3.0 Procedure 0: NULL - Do nothing
void NfsServer::proc_null(const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {
    // No-op.
}

// RFC 1813 §3.3.1 Procedure 1: GETATTR - Get file attributes
void NfsServer::proc_getattr(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    Fattr3 attr;
    NfsStat3 status = vfs_.getattr(fh, attr);
    reply.encode_uint32(static_cast<uint32_t>(status));
    if (status == NfsStat3::NFS3_OK) {
        encode_fattr3(reply, attr);
    }
}

// RFC 1813 §3.3.2 Procedure 2: SETATTR - Set file attributes
void NfsServer::proc_setattr(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    Sattr3 sa = decode_sattr3(args);

    // guard (sattrguard3)
    bool check_guard = args.decode_bool();
    uint32_t guard_sec = 0, guard_nsec = 0;
    if (check_guard) {
        guard_sec = args.decode_uint32();
        guard_nsec = args.decode_uint32();
    }

    // Capture pre-op attributes for WCC
    Fattr3 pre;
    bool have_pre = (vfs_.getattr(fh, pre) == NfsStat3::NFS3_OK);

    // Check guard before applying changes
    if (check_guard) {
        if (!have_pre) {
            reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_STALE));
            encode_wcc_data(reply, fh);
            return;
        }
        if (pre.ctime.seconds != guard_sec ||
            pre.ctime.nseconds != guard_nsec) {
            reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_NOT_SYNC));
            encode_wcc_data(reply, fh, &pre);
            return;
        }
    }

    NfsStat3 status = vfs_.setattr(fh, sa.mode, sa.uid, sa.gid, sa.size,
                                    sa.atime, sa.mtime);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, fh, have_pre ? &pre : nullptr);
}

// RFC 1813 §3.3.3 Procedure 3: LOOKUP - Lookup filename
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

// RFC 1813 §3.3.4 Procedure 4: ACCESS - Check access permission
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

// RFC 1813 §3.3.5 Procedure 5: READLINK - Read from symbolic link
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

// RFC 1813 §3.3.6 Procedure 6: READ - Read from file
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

// RFC 1813 §3.3.7 Procedure 7: WRITE - Write to file
void NfsServer::proc_write(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    uint64_t offset = args.decode_uint64();
    uint32_t count = args.decode_uint32();
    uint32_t stable = args.decode_uint32();
    auto data = args.decode_opaque();

    Fattr3 pre;
    bool have_pre = (vfs_.getattr(fh, pre) == NfsStat3::NFS3_OK);

    // Validate count against data length
    if (data.size() < count) {
        reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_INVAL));
        encode_wcc_data(reply, fh, have_pre ? &pre : nullptr);
        return;
    }

    uint32_t written = 0;
    NfsStat3 status = vfs_.write(fh, offset, data.data(), count, written);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, fh, have_pre ? &pre : nullptr);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint32(written);
        reply.encode_uint32(stable); // echo back requested stability
        reply.encode_uint64(write_verifier_);
    }
}

// RFC 1813 §3.3.8 Procedure 8: CREATE - Create a file
void NfsServer::proc_create(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();
    uint32_t createmode = args.decode_uint32();

    uint32_t mode = 0644;
    if (createmode != EXCLUSIVE) {
        Sattr3 sa = decode_sattr3(args);
        if (sa.mode != UINT32_MAX) mode = sa.mode;
    } else {
        // createverf3: 8 bytes (consumed but not used for now)
        args.decode_uint64();
    }

    Fattr3 dir_pre;
    bool have_pre = (vfs_.getattr(dir_fh, dir_pre) == NfsStat3::NFS3_OK);

    // For GUARDED mode, check if file already exists
    if (createmode == GUARDED) {
        FileHandle existing_fh;
        Fattr3 existing_attr;
        NfsStat3 lookup_stat = vfs_.lookup(dir_fh, name, existing_fh, existing_attr);
        if (lookup_stat == NfsStat3::NFS3_OK) {
            reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_EXIST));
            encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
            return;
        }
    }

    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 status = vfs_.create(dir_fh, name, mode, out_fh, out_attr);
    reply.encode_uint32(static_cast<uint32_t>(status));
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_bool(true);
        reply.encode_opaque(out_fh.data, out_fh.len);
        reply.encode_bool(true);
        encode_fattr3(reply, out_attr);
    }
    encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
}

// RFC 1813 §3.3.9 Procedure 9: MKDIR - Create a directory
void NfsServer::proc_mkdir(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();

    Sattr3 sa = decode_sattr3(args);
    uint32_t mode = (sa.mode != UINT32_MAX) ? sa.mode : 0755u;

    Fattr3 dir_pre;
    bool have_pre = (vfs_.getattr(dir_fh, dir_pre) == NfsStat3::NFS3_OK);

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
    encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
}

// RFC 1813 §3.3.10 Procedure 10: SYMLINK - Create a symbolic link
void NfsServer::proc_symlink(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();
    decode_sattr3(args); // sattr3 for symlink (not applied)
    std::string target = args.decode_string();

    Fattr3 dir_pre;
    bool have_pre = (vfs_.getattr(dir_fh, dir_pre) == NfsStat3::NFS3_OK);

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
    encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
}

// RFC 1813 §3.3.11 Procedure 11: MKNOD - Create a special device
void NfsServer::proc_mknod(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    args.decode_string(); // name

    // Fully consume mknoddata3 to leave decoder in clean state
    uint32_t ftype = args.decode_uint32();
    if (ftype == static_cast<uint32_t>(Ftype3::NF3CHR) ||
        ftype == static_cast<uint32_t>(Ftype3::NF3BLK)) {
        decode_sattr3(args);
        args.decode_uint32(); // specdata major
        args.decode_uint32(); // specdata minor
    } else if (ftype == static_cast<uint32_t>(Ftype3::NF3SOCK) ||
               ftype == static_cast<uint32_t>(Ftype3::NF3FIFO)) {
        decode_sattr3(args);
    }

    Fattr3 dir_pre;
    bool have_pre = (vfs_.getattr(dir_fh, dir_pre) == NfsStat3::NFS3_OK);

    reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_NOTSUPP));
    encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
}

// RFC 1813 §3.3.12 Procedure 12: REMOVE - Remove a file
void NfsServer::proc_remove(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();

    Fattr3 dir_pre;
    bool have_pre = (vfs_.getattr(dir_fh, dir_pre) == NfsStat3::NFS3_OK);

    NfsStat3 status = vfs_.remove(dir_fh, name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
}

// RFC 1813 §3.3.13 Procedure 13: RMDIR - Remove a directory
void NfsServer::proc_rmdir(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();

    Fattr3 dir_pre;
    bool have_pre = (vfs_.getattr(dir_fh, dir_pre) == NfsStat3::NFS3_OK);

    NfsStat3 status = vfs_.rmdir(dir_fh, name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
}

// RFC 1813 §3.3.14 Procedure 14: RENAME - Rename a file or directory
void NfsServer::proc_rename(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle from_dir = decode_fh(args);
    std::string from_name = args.decode_string();
    FileHandle to_dir = decode_fh(args);
    std::string to_name = args.decode_string();

    Fattr3 from_pre, to_pre;
    bool have_from_pre = (vfs_.getattr(from_dir, from_pre) == NfsStat3::NFS3_OK);
    bool have_to_pre = (vfs_.getattr(to_dir, to_pre) == NfsStat3::NFS3_OK);

    NfsStat3 status = vfs_.rename(from_dir, from_name, to_dir, to_name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, from_dir, have_from_pre ? &from_pre : nullptr);
    encode_wcc_data(reply, to_dir, have_to_pre ? &to_pre : nullptr);
}

// RFC 1813 §3.3.15 Procedure 15: LINK - Create link to an object
void NfsServer::proc_link(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    FileHandle dir_fh = decode_fh(args);
    std::string name = args.decode_string();

    Fattr3 dir_pre;
    bool have_pre = (vfs_.getattr(dir_fh, dir_pre) == NfsStat3::NFS3_OK);

    NfsStat3 status = vfs_.link(fh, dir_fh, name);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    encode_wcc_data(reply, dir_fh, have_pre ? &dir_pre : nullptr);
}

// RFC 1813 §3.3.16 Procedure 16: READDIR - Read from directory
void NfsServer::proc_readdir(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    uint64_t cookie = args.decode_uint64();
    uint64_t client_verf = args.decode_uint64();
    uint32_t dircount = args.decode_uint32();

    // Generate cookieverf from directory mtime
    Fattr3 dir_attr;
    uint64_t verf = 0;
    if (vfs_.getattr(dir_fh, dir_attr) == NfsStat3::NFS3_OK) {
        verf = (static_cast<uint64_t>(dir_attr.mtime.seconds) << 32) |
               dir_attr.mtime.nseconds;
    }

    // Validate cookieverf on non-initial requests
    if (cookie != 0 && client_verf != 0 && client_verf != verf) {
        reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_BAD_COOKIE));
        encode_post_op_attr(reply, dir_fh);
        return;
    }

    std::vector<DirEntry> entries;
    bool eof = false;
    NfsStat3 status = vfs_.readdir(dir_fh, cookie, std::min(dircount, 128u), entries, eof);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, dir_fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint64(verf);
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

// RFC 1813 §3.3.17 Procedure 17: READDIRPLUS - Extended read from directory
void NfsServer::proc_readdirplus(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle dir_fh = decode_fh(args);
    uint64_t cookie = args.decode_uint64();
    uint64_t client_verf = args.decode_uint64();
    uint32_t dircount = args.decode_uint32();
    args.decode_uint32(); // maxcount

    // Generate cookieverf from directory mtime
    Fattr3 dir_attr;
    uint64_t verf = 0;
    if (vfs_.getattr(dir_fh, dir_attr) == NfsStat3::NFS3_OK) {
        verf = (static_cast<uint64_t>(dir_attr.mtime.seconds) << 32) |
               dir_attr.mtime.nseconds;
    }

    if (cookie != 0 && client_verf != 0 && client_verf != verf) {
        reply.encode_uint32(static_cast<uint32_t>(NfsStat3::NFS3ERR_BAD_COOKIE));
        encode_post_op_attr(reply, dir_fh);
        return;
    }

    std::vector<DirEntry> entries;
    bool eof = false;
    NfsStat3 status = vfs_.readdir(dir_fh, cookie, std::min(dircount, 128u), entries, eof);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, dir_fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint64(verf);
        for (const auto& e : entries) {
            reply.encode_bool(true); // value follows
            reply.encode_uint64(e.fileid);
            reply.encode_string(e.name);
            reply.encode_uint64(e.cookie);

            // Per-entry post_op_attr and post_op_fh3
            FileHandle entry_fh;
            Fattr3 entry_attr;
            if (vfs_.lookup(dir_fh, e.name, entry_fh, entry_attr) == NfsStat3::NFS3_OK) {
                reply.encode_bool(true);
                encode_fattr3(reply, entry_attr);
                reply.encode_bool(true);
                reply.encode_opaque(entry_fh.data, entry_fh.len);
            } else {
                reply.encode_bool(false);
                reply.encode_bool(false);
            }
        }
        reply.encode_bool(false); // no more entries
        reply.encode_bool(eof);
    }
}

// RFC 1813 §3.3.18 Procedure 18: FSSTAT - Get dynamic file system information
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

// RFC 1813 §3.3.19 Procedure 19: FSINFO - Get static file system information
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
        reply.encode_uint32(4096);    // rtmult: filesystem block size
        reply.encode_uint32(wtmax);
        reply.encode_uint32(wtpref);
        reply.encode_uint32(4096);    // wtmult: filesystem block size
        reply.encode_uint32(dtpref);
        reply.encode_uint64(maxfilesize);
        // time_delta
        reply.encode_uint32(1);  // seconds
        reply.encode_uint32(0);  // nseconds
        // properties bitmask: FSF3_LINK | FSF3_SYMLINK | FSF3_HOMOGENEOUS | FSF3_CANSETTIME
        reply.encode_uint32(0x001B);
    }
}

// RFC 1813 §3.3.20 Procedure 20: PATHCONF - Retrieve POSIX information
void NfsServer::proc_pathconf(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);

    uint32_t linkmax, name_max;
    NfsStat3 status = vfs_.pathconf(fh, linkmax, name_max);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_post_op_attr(reply, fh);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint32(linkmax);
        reply.encode_uint32(name_max);
        reply.encode_bool(true);   // no_trunc
        reply.encode_bool(true);   // chown_restricted
        reply.encode_bool(false);  // case_insensitive: Linux is case-sensitive
        reply.encode_bool(true);   // case_preserving
    }
}

// RFC 1813 §3.3.21 Procedure 21: COMMIT - Commit cached data on a server to stable storage
void NfsServer::proc_commit(const RpcCallHeader&, XdrDecoder& args, XdrEncoder& reply) {
    FileHandle fh = decode_fh(args);
    uint64_t offset = args.decode_uint64();
    uint32_t count = args.decode_uint32();

    Fattr3 pre;
    bool have_pre = (vfs_.getattr(fh, pre) == NfsStat3::NFS3_OK);

    NfsStat3 status = vfs_.commit(fh, offset, count);
    reply.encode_uint32(static_cast<uint32_t>(status));
    encode_wcc_data(reply, fh, have_pre ? &pre : nullptr);
    if (status == NfsStat3::NFS3_OK) {
        reply.encode_uint64(write_verifier_);
    }
}
