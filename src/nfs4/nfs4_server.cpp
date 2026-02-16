#include "nfs4/nfs4_server.h"
#include "nfs4/nfs4_attrs.h"
#include "nfs4/nfs4_callback.h"
#include "nfs4/nfs4_types.h"
#include <chrono>
#include <cstring>
#include <iostream>

// RFC 7530 §14.1 - UTF-8 string validation
static bool is_valid_utf8(const std::string& s) {
    const auto* p = reinterpret_cast<const uint8_t*>(s.data());
    const auto* end = p + s.size();
    while (p < end) {
        if (*p < 0x80) { p++; }
        else if ((*p & 0xE0) == 0xC0) {
            if (p + 1 >= end || (p[1] & 0xC0) != 0x80) return false;
            if (*p < 0xC2) return false; // overlong
            p += 2;
        } else if ((*p & 0xF0) == 0xE0) {
            if (p + 2 >= end || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return false;
            uint32_t cp = ((*p & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
            p += 3;
        } else if ((*p & 0xF8) == 0xF0) {
            if (p + 3 >= end || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) return false;
            uint32_t cp = ((*p & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF) return false;
            p += 4;
        } else {
            return false;
        }
    }
    return true;
}

// RFC 7530 - NFS Version 4 Protocol Server Implementation

Nfs4Server::Nfs4Server(Vfs& vfs, const std::string& export_root)
    : vfs_(vfs), export_root_(export_root) {
    // Cache root file handle
    vfs_.get_root_fh("/", root_fh_);

    // Write verifier (server boot time)
    auto now = std::chrono::system_clock::now().time_since_epoch();
    write_verifier_ = std::chrono::duration_cast<std::chrono::microseconds>(now).count();

    // Register operation handlers
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_ACCESS)]              = &Nfs4Server::op_access;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_CLOSE)]               = &Nfs4Server::op_close;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_COMMIT)]              = &Nfs4Server::op_commit;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_CREATE)]              = &Nfs4Server::op_create;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_GETATTR)]             = &Nfs4Server::op_getattr;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_GETFH)]               = &Nfs4Server::op_getfh;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_LINK)]                = &Nfs4Server::op_link;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_LOCK)]               = &Nfs4Server::op_lock;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_LOCKT)]              = &Nfs4Server::op_lockt;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_LOCKU)]              = &Nfs4Server::op_locku;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_LOOKUP)]              = &Nfs4Server::op_lookup;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_LOOKUPP)]             = &Nfs4Server::op_lookupp;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_OPEN)]                = &Nfs4Server::op_open;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_OPEN_CONFIRM)]        = &Nfs4Server::op_open_confirm;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_OPEN_DOWNGRADE)]     = &Nfs4Server::op_open_downgrade;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_PUTFH)]               = &Nfs4Server::op_putfh;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_PUTROOTFH)]           = &Nfs4Server::op_putrootfh;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_READ)]                = &Nfs4Server::op_read;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_READDIR)]             = &Nfs4Server::op_readdir;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_READLINK)]            = &Nfs4Server::op_readlink;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_REMOVE)]              = &Nfs4Server::op_remove;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_RENAME)]              = &Nfs4Server::op_rename;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_RENEW)]               = &Nfs4Server::op_renew;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_RESTOREFH)]           = &Nfs4Server::op_restorefh;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_SAVEFH)]              = &Nfs4Server::op_savefh;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_SETATTR)]             = &Nfs4Server::op_setattr;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_SETCLIENTID)]         = &Nfs4Server::op_setclientid;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_SETCLIENTID_CONFIRM)] = &Nfs4Server::op_setclientid_confirm;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_VERIFY)]             = &Nfs4Server::op_verify;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_NVERIFY)]             = &Nfs4Server::op_nverify;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_RELEASE_LOCKOWNER)]  = &Nfs4Server::op_release_lockowner;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_WRITE)]               = &Nfs4Server::op_write;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_DELEGRETURN)]         = &Nfs4Server::op_delegreturn;
    op_handlers_[static_cast<uint32_t>(Nfs4Op::OP_DELEGPURGE)]          = &Nfs4Server::op_delegpurge;
}

RpcProgramHandlers Nfs4Server::get_handlers() {
    RpcProgramHandlers h;
    h.procedures[NFSPROC4_NULL] = [this](auto& c, auto& a, auto& r) { proc_null(c, a, r); };
    h.procedures[NFSPROC4_COMPOUND] = [this](auto& c, auto& a, auto& r) { proc_compound(c, a, r); };
    return h;
}

// RFC 7530 §16.1 Procedure 0: NULL
void Nfs4Server::proc_null(const RpcCallHeader&, XdrDecoder&, XdrEncoder&) {
    // No-op
}

// RFC 7530 §16.2 Procedure 1: COMPOUND
void Nfs4Server::proc_compound(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply) {
    std::string tag = args.decode_string();
    uint32_t minorversion = args.decode_uint32();
    uint32_t num_ops = args.decode_uint32();

    if (minorversion != 0) {
        reply.encode_uint32(static_cast<uint32_t>(Nfs4Stat::NFS4ERR_MINOR_VERS_MISMATCH));
        reply.encode_string(tag);
        reply.encode_uint32(0);
        return;
    }

    CompoundState cs;

    // Extract AUTH_SYS credentials if present
    if (call.credential.flavor == RpcAuthFlavor::AUTH_SYS) {
        auto auth = RpcServer::parse_auth_sys(call.credential);
        cs.uid = auth.uid;
        cs.gid = auth.gid;
        cs.gids = auth.gids;
    }
    Nfs4Stat last_status = Nfs4Stat::NFS4_OK;

    // Buffer individual op results, then assemble the final reply
    struct OpResult {
        uint32_t opcode;
        Nfs4Stat status;
        std::vector<uint8_t> data;
    };
    std::vector<OpResult> results;

    for (uint32_t i = 0; i < num_ops; i++) {
        uint32_t opcode = args.decode_uint32();
        XdrEncoder op_enc;

        auto it = op_handlers_.find(opcode);
        Nfs4Stat status;
        if (it == op_handlers_.end()) {
            status = Nfs4Stat::NFS4ERR_OP_ILLEGAL;
            opcode = static_cast<uint32_t>(Nfs4Op::OP_ILLEGAL);
        } else {
            try {
                status = (this->*(it->second))(cs, args, op_enc);
            } catch (const std::exception& e) {
                status = Nfs4Stat::NFS4ERR_SERVERFAULT;
            }
        }

        OpResult r;
        r.opcode = opcode;
        r.status = status;
        r.data = std::vector<uint8_t>(op_enc.data().begin(), op_enc.data().end());
        results.push_back(std::move(r));

        last_status = status;
        if (status != Nfs4Stat::NFS4_OK)
            break;
    }

    // Encode COMPOUND reply
    reply.encode_uint32(static_cast<uint32_t>(last_status));
    reply.encode_string(tag);
    reply.encode_uint32(static_cast<uint32_t>(results.size()));

    for (const auto& r : results) {
        reply.encode_uint32(r.opcode);
        reply.encode_uint32(static_cast<uint32_t>(r.status));
        if (!r.data.empty())
            reply.encode_opaque_fixed(r.data.data(), r.data.size());
    }
}

// --- Helper methods ---

Nfs4Stat Nfs4Server::decode_stateid(XdrDecoder& args, Nfs4StateId& sid) {
    sid.seqid = args.decode_uint32();
    args.decode_opaque_fixed(sid.other, 12);
    return Nfs4Stat::NFS4_OK;
}

void Nfs4Server::encode_change_info(XdrEncoder& enc, const FileHandle& dir_fh) {
    Fattr3 attr;
    uint64_t change = 0;
    if (vfs_.getattr(dir_fh, attr) == NfsStat3::NFS3_OK) {
        change = (static_cast<uint64_t>(attr.mtime.seconds) << 32) | attr.mtime.nseconds;
    }
    enc.encode_bool(false);     // atomic = false
    enc.encode_uint64(change);  // before (approximation)
    enc.encode_uint64(change);  // after (approximation)
}

// --- Filehandle operations ---

// RFC 7530 §16.20 - PUTROOTFH
Nfs4Stat Nfs4Server::op_putrootfh(CompoundState& cs, XdrDecoder&, XdrEncoder&) {
    cs.current_fh = root_fh_;
    cs.current_fh_set = true;
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.19 - PUTFH
Nfs4Stat Nfs4Server::op_putfh(CompoundState& cs, XdrDecoder& args, XdrEncoder&) {
    auto opaque = args.decode_opaque();
    FileHandle fh;
    fh.len = std::min(opaque.size(), sizeof(fh.data));
    std::memcpy(fh.data, opaque.data(), fh.len);
    cs.current_fh = fh;
    cs.current_fh_set = true;
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.10 - GETFH
Nfs4Stat Nfs4Server::op_getfh(CompoundState& cs, XdrDecoder&, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;
    enc.encode_opaque(cs.current_fh.data, cs.current_fh.len);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.28 - SAVEFH
Nfs4Stat Nfs4Server::op_savefh(CompoundState& cs, XdrDecoder&, XdrEncoder&) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;
    cs.saved_fh = cs.current_fh;
    cs.saved_fh_set = true;
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.27 - RESTOREFH
Nfs4Stat Nfs4Server::op_restorefh(CompoundState& cs, XdrDecoder&, XdrEncoder&) {
    if (!cs.saved_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;
    cs.current_fh = cs.saved_fh;
    cs.current_fh_set = true;
    return Nfs4Stat::NFS4_OK;
}

// --- Read-only operations ---

// RFC 7530 §16.9 - GETATTR
Nfs4Stat Nfs4Server::op_getattr(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    auto requested = decode_bitmap(args);

    Fattr3 attr;
    NfsStat3 s = vfs_.getattr(cs.current_fh, attr);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    encode_fattr4(enc, requested, attr, cs.current_fh);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.3 - ACCESS
Nfs4Stat Nfs4Server::op_access(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    uint32_t requested = args.decode_uint32();
    uint32_t granted = 0;
    NfsStat3 s = vfs_.access(cs.current_fh, requested, granted);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    enc.encode_uint32(requested); // supported
    enc.encode_uint32(granted);   // access
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.15 - LOOKUP
Nfs4Stat Nfs4Server::op_lookup(CompoundState& cs, XdrDecoder& args, XdrEncoder&) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    std::string name = args.decode_string();
    if (!is_valid_utf8(name)) return Nfs4Stat::NFS4ERR_INVAL;
    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 s = vfs_.lookup(cs.current_fh, name, out_fh, out_attr);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    cs.current_fh = out_fh;
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.16 - LOOKUPP (lookup parent)
Nfs4Stat Nfs4Server::op_lookupp(CompoundState& cs, XdrDecoder&, XdrEncoder&) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 s = vfs_.lookup(cs.current_fh, "..", out_fh, out_attr);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    cs.current_fh = out_fh;
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.23 - READDIR
Nfs4Stat Nfs4Server::op_readdir(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    uint64_t cookie = args.decode_uint64();
    uint64_t client_verf = args.decode_uint64();
    uint32_t dircount = args.decode_uint32();
    args.decode_uint32(); // maxcount
    auto attr_request = decode_bitmap(args);

    // Generate cookieverf from directory mtime
    Fattr3 dir_attr;
    uint64_t verf = 0;
    if (vfs_.getattr(cs.current_fh, dir_attr) == NfsStat3::NFS3_OK) {
        verf = (static_cast<uint64_t>(dir_attr.mtime.seconds) << 32) |
               dir_attr.mtime.nseconds;
    }

    // Validate cookieverf on non-initial requests
    if (cookie != 0 && client_verf != 0 && client_verf != verf)
        return Nfs4Stat::NFS4ERR_BAD_COOKIE;

    std::vector<DirEntry> entries;
    bool eof = false;
    NfsStat3 s = vfs_.readdir(cs.current_fh, cookie, std::min(dircount, 128u), entries, eof);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    // cookieverf
    enc.encode_uint64(verf);

    // Entries
    for (const auto& e : entries) {
        enc.encode_bool(true); // value follows

        enc.encode_uint64(e.cookie);
        enc.encode_string(e.name);

        // Per-entry attributes: look up attrs for each entry
        FileHandle entry_fh;
        Fattr3 entry_attr;
        if (vfs_.lookup(cs.current_fh, e.name, entry_fh, entry_attr) == NfsStat3::NFS3_OK) {
            encode_fattr4(enc, attr_request, entry_attr, entry_fh);
        } else {
            // Encode empty attrs on lookup failure
            std::vector<uint32_t> empty_bm;
            encode_bitmap(enc, empty_bm);
            enc.encode_uint32(0); // empty attr data
        }
    }
    enc.encode_bool(false); // no more entries
    enc.encode_bool(eof);

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.12 - LINK
Nfs4Stat Nfs4Server::op_link(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    // saved_fh = source file, current_fh = target directory
    if (!cs.saved_fh_set || !cs.current_fh_set)
        return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    std::string newname = args.decode_string();
    if (!is_valid_utf8(newname)) return Nfs4Stat::NFS4ERR_INVAL;

    // Get before change info for target directory
    Fattr3 before_attr;
    vfs_.getattr(cs.current_fh, before_attr);
    uint64_t change_before = (static_cast<uint64_t>(before_attr.mtime.seconds) << 32) |
                              before_attr.mtime.nseconds;

    NfsStat3 s = vfs_.link(cs.saved_fh, cs.current_fh, newname);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    // Get after change info
    Fattr3 after_attr;
    vfs_.getattr(cs.current_fh, after_attr);
    uint64_t change_after = (static_cast<uint64_t>(after_attr.mtime.seconds) << 32) |
                             after_attr.mtime.nseconds;

    // change_info4
    enc.encode_bool(false);
    enc.encode_uint64(change_before);
    enc.encode_uint64(change_after);

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.24 - READLINK
Nfs4Stat Nfs4Server::op_readlink(CompoundState& cs, XdrDecoder&, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    std::string target;
    NfsStat3 s = vfs_.readlink(cs.current_fh, target);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    enc.encode_string(target);
    return Nfs4Stat::NFS4_OK;
}

// --- Client state operations ---

// RFC 7530 §16.33 - SETCLIENTID
Nfs4Stat Nfs4Server::op_setclientid(CompoundState&, XdrDecoder& args, XdrEncoder& enc) {
    // nfs_client_id4: verifier (8 bytes) + id (opaque)
    uint8_t verifier[8];
    args.decode_opaque_fixed(verifier, 8);
    auto client_id_opaque = args.decode_opaque();

    // callback: cb_program (uint32) + cb_location (r_netid + r_addr)
    Nfs4CallbackInfo cb;
    cb.cb_program = args.decode_uint32();
    cb.r_netid = args.decode_string();
    cb.r_addr = args.decode_string();
    cb.callback_ident = args.decode_uint32();
    cb.valid = !cb.r_addr.empty() && !cb.r_netid.empty();

    auto [clientid, confirm] = state_.set_clientid(verifier, client_id_opaque, cb);

    enc.encode_uint64(clientid);
    enc.encode_opaque_fixed(confirm.data(), 8);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.34 - SETCLIENTID_CONFIRM
Nfs4Stat Nfs4Server::op_setclientid_confirm(CompoundState&, XdrDecoder& args, XdrEncoder&) {
    uint64_t clientid = args.decode_uint64();
    uint8_t confirm[8];
    args.decode_opaque_fixed(confirm, 8);

    Nfs4Stat s = state_.confirm_clientid(clientid, confirm);
    if (s != Nfs4Stat::NFS4_OK) return s;

    // RFC 7530 §16.34 - Probe callback path
    Nfs4CallbackInfo cb = state_.get_client_callback(clientid);
    if (cb.valid) {
        bool ok = cb_null_probe(cb, next_cb_xid_++);
        if (!ok) {
            std::cerr << "CB_NULL probe failed for client " << clientid
                      << " at " << cb.r_addr << " — delegations disabled\n";
            state_.invalidate_client_callback(clientid);
        }
    }
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.27 - RENEW
Nfs4Stat Nfs4Server::op_renew(CompoundState&, XdrDecoder& args, XdrEncoder&) {
    uint64_t clientid = args.decode_uint64();
    return state_.renew(clientid);
}

// --- Stateful file operations ---

// RFC 7530 §16.16 - OPEN
Nfs4Stat Nfs4Server::op_open(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    uint32_t seqid = args.decode_uint32();
    uint32_t share_access = args.decode_uint32();
    uint32_t share_deny = args.decode_uint32();

    // open_owner4: clientid + owner
    uint64_t clientid = args.decode_uint64();
    auto owner = args.decode_opaque();

    // openhow4
    uint32_t opentype = args.decode_uint32();
    uint32_t create_mode = 0;
    uint32_t file_mode = 0644;
    uint64_t create_verf = 0;
    if (opentype == OPEN4_CREATE) {
        create_mode = args.decode_uint32();
        if (create_mode == UNCHECKED4 || create_mode == GUARDED4) {
            // fattr4 for creation attributes
            auto sa = decode_fattr4_setattr(args);
            if (sa.mode != UINT32_MAX) file_mode = sa.mode;
        } else if (create_mode == EXCLUSIVE4) {
            create_verf = args.decode_uint64();
        }
    }

    // open_claim4
    uint32_t claim_type = args.decode_uint32();
    std::string name;
    Nfs4StateId deleg_cur_stateid;
    if (claim_type == CLAIM_NULL) {
        name = args.decode_string();
        if (!is_valid_utf8(name)) return Nfs4Stat::NFS4ERR_INVAL;
    } else if (claim_type == CLAIM_PREVIOUS) {
        args.decode_uint32(); // delegate_type
        return Nfs4Stat::NFS4ERR_NO_GRACE;
    } else if (claim_type == CLAIM_DELEGATE_CUR) {
        decode_stateid(args, deleg_cur_stateid);
        name = args.decode_string();
        if (!is_valid_utf8(name)) return Nfs4Stat::NFS4ERR_INVAL;
        // Validate the delegation stateid
        Nfs4Stat vs = state_.validate_stateid(deleg_cur_stateid, share_access);
        if (vs != Nfs4Stat::NFS4_OK) return vs;
    } else if (claim_type == CLAIM_DELEGATE_PREV) {
        name = args.decode_string();
        if (!is_valid_utf8(name)) return Nfs4Stat::NFS4ERR_INVAL;
        return Nfs4Stat::NFS4ERR_NO_GRACE;
    } else {
        return Nfs4Stat::NFS4ERR_NOTSUPP;
    }

    // Save dir for change_info
    FileHandle dir_fh = cs.current_fh;

    // Get before change info
    Fattr3 before_attr;
    vfs_.getattr(dir_fh, before_attr);
    uint64_t change_before = (static_cast<uint64_t>(before_attr.mtime.seconds) << 32) |
                              before_attr.mtime.nseconds;

    // Look up or create the file
    FileHandle file_fh;
    Fattr3 file_attr;
    NfsStat3 lookup_s = vfs_.lookup(dir_fh, name, file_fh, file_attr);

    if (opentype == OPEN4_CREATE) {
        if (create_mode == GUARDED4 && lookup_s == NfsStat3::NFS3_OK) {
            return Nfs4Stat::NFS4ERR_EXIST;
        }
        if (create_mode == EXCLUSIVE4 && lookup_s == NfsStat3::NFS3_OK) {
            // RFC 7530 §16.16.4 - EXCLUSIVE4: if file exists, check verifier
            // stored in atime/mtime. If matches, return success (replay).
            uint32_t v_hi = static_cast<uint32_t>(create_verf >> 32);
            uint32_t v_lo = static_cast<uint32_t>(create_verf & 0xFFFFFFFF);
            if (file_attr.atime.seconds != v_hi || file_attr.mtime.seconds != v_lo) {
                return Nfs4Stat::NFS4ERR_EXIST;
            }
            // Verifier matches — treat as successful replay
        } else if (lookup_s != NfsStat3::NFS3_OK) {
            // Create the file
            NfsStat3 cs2 = vfs_.create(dir_fh, name, file_mode, file_fh, file_attr);
            if (cs2 != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(cs2);
            if (create_mode == EXCLUSIVE4) {
                // Store verifier in atime/mtime
                NfsTimeSet at, mt;
                at.how = NfsTimeSet::How::SET_TO_CLIENT_TIME;
                at.time.seconds = static_cast<uint32_t>(create_verf >> 32);
                at.time.nseconds = 0;
                mt.how = NfsTimeSet::How::SET_TO_CLIENT_TIME;
                mt.time.seconds = static_cast<uint32_t>(create_verf & 0xFFFFFFFF);
                mt.time.nseconds = 0;
                vfs_.setattr(file_fh, UINT32_MAX, UINT32_MAX, UINT32_MAX,
                             UINT64_MAX, at, mt);
            }
        }
    } else {
        // NOCREATE - file must exist
        if (lookup_s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(lookup_s);
    }

    // Create open state (with delegation support)
    Nfs4StateId stateid;
    bool needs_confirm = false;
    uint32_t deleg_type = OPEN_DELEGATE_NONE;
    Nfs4StateId deleg_stateid;
    Nfs4CallbackInfo recall_cb;
    Nfs4StateId recall_deleg_sid;
    FileHandle recall_fh;

    Nfs4Stat s = state_.open_file(clientid, owner, seqid, file_fh,
                                   share_access, share_deny,
                                   stateid, needs_confirm,
                                   deleg_type, deleg_stateid,
                                   recall_cb, recall_deleg_sid, recall_fh);

    if (s == Nfs4Stat::NFS4ERR_DELAY) {
        // Delegation conflict — send CB_RECALL and tell client to retry
        if (recall_cb.valid)
            cb_recall(recall_cb, next_cb_xid_++, recall_deleg_sid, false, recall_fh);
        return Nfs4Stat::NFS4ERR_DELAY;
    }
    if (s != Nfs4Stat::NFS4_OK) return s;

    // Update current FH to the opened file
    cs.current_fh = file_fh;

    // Get after change info
    Fattr3 after_attr;
    vfs_.getattr(dir_fh, after_attr);
    uint64_t change_after = (static_cast<uint64_t>(after_attr.mtime.seconds) << 32) |
                             after_attr.mtime.nseconds;

    // Encode OPEN4resok
    // stateid4
    enc.encode_uint32(stateid.seqid);
    enc.encode_opaque_fixed(stateid.other, 12);

    // change_info4
    enc.encode_bool(false);            // atomic
    enc.encode_uint64(change_before);  // before
    enc.encode_uint64(change_after);   // after

    // rflags
    uint32_t rflags = 0;
    if (needs_confirm) rflags |= OPEN4_RESULT_CONFIRM;
    enc.encode_uint32(rflags);

    // attrset bitmap (for CREATE: what attrs were set)
    std::vector<uint32_t> attrset;
    encode_bitmap(enc, attrset);

    // delegation
    enc.encode_uint32(deleg_type);
    if (deleg_type == OPEN_DELEGATE_READ) {
        // open_read_delegation4: stateid, recall, nfsace4
        enc.encode_uint32(deleg_stateid.seqid);
        enc.encode_opaque_fixed(deleg_stateid.other, 12);
        enc.encode_bool(false);  // recall = false
        // nfsace4: type=ALLOW(0), flag=0, access_mask=READ_DATA(1), who=""
        enc.encode_uint32(0);          // ACE4_ACCESS_ALLOWED_ACE_TYPE
        enc.encode_uint32(0);          // aceflag
        enc.encode_uint32(0x00000001); // ACE4_READ_DATA
        enc.encode_string("");         // who
    } else if (deleg_type == OPEN_DELEGATE_WRITE) {
        // open_write_delegation4: stateid, recall, space_limit, nfsace4
        enc.encode_uint32(deleg_stateid.seqid);
        enc.encode_opaque_fixed(deleg_stateid.other, 12);
        enc.encode_bool(false);  // recall = false
        // space_limit: limitby=NFS_LIMIT_SIZE, filesize=unlimited
        enc.encode_uint32(NFS_LIMIT_SIZE);
        enc.encode_uint64(UINT64_MAX);
        // nfsace4: type=ALLOW(0), flag=0, access_mask=READ|WRITE(0x6), who=""
        enc.encode_uint32(0);
        enc.encode_uint32(0);
        enc.encode_uint32(0x00000006); // ACE4_READ_DATA | ACE4_WRITE_DATA
        enc.encode_string("");
    }

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.18 - OPEN_CONFIRM
Nfs4Stat Nfs4Server::op_open_confirm(CompoundState&, XdrDecoder& args, XdrEncoder& enc) {
    Nfs4StateId stateid;
    decode_stateid(args, stateid);
    uint32_t seqid = args.decode_uint32();

    Nfs4StateId out_stateid;
    Nfs4Stat s = state_.confirm_open(stateid, seqid, out_stateid);
    if (s != Nfs4Stat::NFS4_OK) return s;

    // Encode stateid
    enc.encode_uint32(out_stateid.seqid);
    enc.encode_opaque_fixed(out_stateid.other, 12);
    return Nfs4Stat::NFS4_OK;
}

// Helper: encode LOCK4denied
static void encode_lock_denied(XdrEncoder& enc, const Nfs4LockDenied& denied) {
    enc.encode_uint64(denied.offset);
    enc.encode_uint64(denied.length);
    enc.encode_uint32(denied.locktype);
    enc.encode_uint64(denied.owner.clientid);
    enc.encode_opaque(denied.owner.owner.data(), denied.owner.owner.size());
}

// RFC 7530 §16.10 - LOCK
Nfs4Stat Nfs4Server::op_lock(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    uint32_t locktype = args.decode_uint32();
    bool reclaim = args.decode_bool();
    uint64_t offset = args.decode_uint64();
    uint64_t length = args.decode_uint64();

    // Normalize wait variants
    if (locktype == READW_LT) locktype = READ_LT;
    if (locktype == WRITEW_LT) locktype = WRITE_LT;

    bool new_lock_owner = args.decode_bool();

    if (reclaim)
        return Nfs4Stat::NFS4ERR_NO_GRACE;

    Nfs4StateId out_stateid;
    Nfs4LockDenied denied;
    Nfs4Stat s;

    if (new_lock_owner) {
        uint32_t open_seqid = args.decode_uint32();
        Nfs4StateId open_stateid;
        decode_stateid(args, open_stateid);
        uint32_t lock_seqid = args.decode_uint32();
        // lock_owner: clientid + owner
        uint64_t clientid = args.decode_uint64();
        auto owner = args.decode_opaque();

        Nfs4LockOwner lo;
        lo.clientid = clientid;
        lo.owner = owner;

        s = state_.lock_new(clientid, open_stateid, open_seqid,
                            lo, lock_seqid, cs.current_fh,
                            locktype, offset, length,
                            out_stateid, denied);
    } else {
        Nfs4StateId lock_stateid;
        decode_stateid(args, lock_stateid);
        uint32_t lock_seqid = args.decode_uint32();

        s = state_.lock_existing(lock_stateid, lock_seqid,
                                 locktype, offset, length,
                                 out_stateid, denied);
    }

    if (s == Nfs4Stat::NFS4_OK) {
        enc.encode_uint32(out_stateid.seqid);
        enc.encode_opaque_fixed(out_stateid.other, 12);
    } else if (s == Nfs4Stat::NFS4ERR_DENIED) {
        encode_lock_denied(enc, denied);
    }

    return s;
}

// RFC 7530 §16.11 - LOCKT
Nfs4Stat Nfs4Server::op_lockt(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    uint32_t locktype = args.decode_uint32();
    uint64_t offset = args.decode_uint64();
    uint64_t length = args.decode_uint64();
    uint64_t clientid = args.decode_uint64();
    auto owner = args.decode_opaque();

    if (locktype == READW_LT) locktype = READ_LT;
    if (locktype == WRITEW_LT) locktype = WRITE_LT;

    Nfs4LockOwner lo;
    lo.clientid = clientid;
    lo.owner = owner;

    Nfs4LockDenied denied;
    Nfs4Stat s = state_.lock_test(cs.current_fh, locktype, offset, length, lo, denied);

    if (s == Nfs4Stat::NFS4ERR_DENIED) {
        encode_lock_denied(enc, denied);
    }

    return s;
}

// RFC 7530 §16.12 - LOCKU
Nfs4Stat Nfs4Server::op_locku(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    uint32_t locktype = args.decode_uint32();
    (void)locktype;  // locktype not used for unlock
    uint32_t seqid = args.decode_uint32();
    Nfs4StateId lock_stateid;
    decode_stateid(args, lock_stateid);
    uint64_t offset = args.decode_uint64();
    uint64_t length = args.decode_uint64();

    Nfs4StateId out_stateid;
    Nfs4Stat s = state_.lock_unlock(lock_stateid, seqid, offset, length, out_stateid);
    if (s != Nfs4Stat::NFS4_OK) return s;

    enc.encode_uint32(out_stateid.seqid);
    enc.encode_opaque_fixed(out_stateid.other, 12);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.26 - RELEASE_LOCKOWNER
Nfs4Stat Nfs4Server::op_release_lockowner(CompoundState&, XdrDecoder& args, XdrEncoder&) {
    uint64_t clientid = args.decode_uint64();
    auto owner = args.decode_opaque();

    Nfs4LockOwner lo;
    lo.clientid = clientid;
    lo.owner = owner;

    return state_.release_lock_owner(lo);
}

// RFC 7530 §16.19 - OPEN_DOWNGRADE
Nfs4Stat Nfs4Server::op_open_downgrade(CompoundState&, XdrDecoder& args, XdrEncoder& enc) {
    Nfs4StateId stateid;
    decode_stateid(args, stateid);
    uint32_t seqid = args.decode_uint32();
    uint32_t share_access = args.decode_uint32();
    uint32_t share_deny = args.decode_uint32();

    Nfs4StateId out_stateid;
    Nfs4Stat s = state_.open_downgrade(stateid, seqid, share_access, share_deny, out_stateid);
    if (s != Nfs4Stat::NFS4_OK) return s;

    enc.encode_uint32(out_stateid.seqid);
    enc.encode_opaque_fixed(out_stateid.other, 12);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.4 - CLOSE
Nfs4Stat Nfs4Server::op_close(CompoundState&, XdrDecoder& args, XdrEncoder& enc) {
    uint32_t seqid = args.decode_uint32();
    Nfs4StateId stateid;
    decode_stateid(args, stateid);

    Nfs4StateId out_stateid;
    Nfs4Stat s = state_.close_file(stateid, seqid, out_stateid);
    if (s != Nfs4Stat::NFS4_OK) return s;

    enc.encode_uint32(out_stateid.seqid);
    enc.encode_opaque_fixed(out_stateid.other, 12);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.22 - READ
Nfs4Stat Nfs4Server::op_read(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    Nfs4StateId stateid;
    decode_stateid(args, stateid);
    uint64_t offset = args.decode_uint64();
    uint32_t count = args.decode_uint32();

    // Validate stateid
    Nfs4Stat vs = state_.validate_stateid(stateid, OPEN4_SHARE_ACCESS_READ);
    if (vs != Nfs4Stat::NFS4_OK) return vs;

    std::vector<uint8_t> data;
    bool eof = false;
    NfsStat3 s = vfs_.read(cs.current_fh, offset, count, data, eof);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    enc.encode_bool(eof);
    enc.encode_opaque(data.data(), data.size());
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.32 - WRITE
Nfs4Stat Nfs4Server::op_write(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    Nfs4StateId stateid;
    decode_stateid(args, stateid);
    uint64_t offset = args.decode_uint64();
    uint32_t stable = args.decode_uint32();
    auto data = args.decode_opaque();

    // Validate stateid
    Nfs4Stat vs = state_.validate_stateid(stateid, OPEN4_SHARE_ACCESS_WRITE);
    if (vs != Nfs4Stat::NFS4_OK) return vs;

    uint32_t written = 0;
    NfsStat3 s = vfs_.write(cs.current_fh, offset, data.data(),
                             static_cast<uint32_t>(data.size()), written);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    enc.encode_uint32(written);
    enc.encode_uint32(stable); // echo back committed level
    enc.encode_uint64(write_verifier_);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.5 - COMMIT
Nfs4Stat Nfs4Server::op_commit(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    uint64_t offset = args.decode_uint64();
    uint32_t count = args.decode_uint32();

    NfsStat3 s = vfs_.commit(cs.current_fh, offset, count);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    enc.encode_uint64(write_verifier_);
    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.30 - SETATTR
Nfs4Stat Nfs4Server::op_setattr(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    Nfs4StateId stateid;
    decode_stateid(args, stateid);

    auto sa = decode_fattr4_setattr(args);

    NfsStat3 s = vfs_.setattr(cs.current_fh, sa.mode, sa.uid, sa.gid, sa.size,
                               sa.atime, sa.mtime);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    // attrsset bitmap (what was actually set)
    std::vector<uint32_t> attrsset;
    if (sa.mode != UINT32_MAX) bitmap_set(attrsset, FATTR4_MODE);
    if (sa.size != UINT64_MAX) bitmap_set(attrsset, FATTR4_SIZE);
    encode_bitmap(enc, attrsset);

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.6 - CREATE (for mkdir, symlink, etc.)
Nfs4Stat Nfs4Server::op_create(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    uint32_t type = args.decode_uint32();

    // Type-specific data
    std::string linkdata;
    if (type == static_cast<uint32_t>(Nfs4Type::NF4LNK)) {
        linkdata = args.decode_string();
    } else if (type == static_cast<uint32_t>(Nfs4Type::NF4BLK) ||
               type == static_cast<uint32_t>(Nfs4Type::NF4CHR)) {
        args.decode_uint32(); // specdata major
        args.decode_uint32(); // specdata minor
    }

    std::string name = args.decode_string();
    if (!is_valid_utf8(name)) return Nfs4Stat::NFS4ERR_INVAL;

    // createattrs (fattr4)
    auto sa = decode_fattr4_setattr(args);
    uint32_t mode = (sa.mode != UINT32_MAX) ? sa.mode : 0755u;

    FileHandle dir_fh = cs.current_fh;

    // Get before change info
    Fattr3 before_attr;
    vfs_.getattr(dir_fh, before_attr);
    uint64_t change_before = (static_cast<uint64_t>(before_attr.mtime.seconds) << 32) |
                              before_attr.mtime.nseconds;

    FileHandle out_fh;
    Fattr3 out_attr;
    NfsStat3 s;

    if (type == static_cast<uint32_t>(Nfs4Type::NF4DIR)) {
        s = vfs_.mkdir(dir_fh, name, mode, out_fh, out_attr);
    } else if (type == static_cast<uint32_t>(Nfs4Type::NF4LNK)) {
        s = vfs_.symlink(dir_fh, name, linkdata, out_fh, out_attr);
    } else {
        return Nfs4Stat::NFS4ERR_NOTSUPP;
    }

    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    cs.current_fh = out_fh;

    // Get after change info
    Fattr3 after_attr;
    vfs_.getattr(dir_fh, after_attr);
    uint64_t change_after = (static_cast<uint64_t>(after_attr.mtime.seconds) << 32) |
                             after_attr.mtime.nseconds;

    // change_info4
    enc.encode_bool(false);
    enc.encode_uint64(change_before);
    enc.encode_uint64(change_after);

    // attrset bitmap
    std::vector<uint32_t> attrset;
    encode_bitmap(enc, attrset);

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.25 - REMOVE
Nfs4Stat Nfs4Server::op_remove(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    std::string name = args.decode_string();
    if (!is_valid_utf8(name)) return Nfs4Stat::NFS4ERR_INVAL;

    // Get before change info
    Fattr3 before_attr;
    vfs_.getattr(cs.current_fh, before_attr);
    uint64_t change_before = (static_cast<uint64_t>(before_attr.mtime.seconds) << 32) |
                              before_attr.mtime.nseconds;

    // Try remove as file first, then as directory
    NfsStat3 s = vfs_.remove(cs.current_fh, name);
    if (s == NfsStat3::NFS3ERR_ISDIR || s == NfsStat3::NFS3ERR_PERM) {
        s = vfs_.rmdir(cs.current_fh, name);
    }
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    // Get after change info
    Fattr3 after_attr;
    vfs_.getattr(cs.current_fh, after_attr);
    uint64_t change_after = (static_cast<uint64_t>(after_attr.mtime.seconds) << 32) |
                             after_attr.mtime.nseconds;

    // change_info4
    enc.encode_bool(false);
    enc.encode_uint64(change_before);
    enc.encode_uint64(change_after);

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.26 - RENAME
Nfs4Stat Nfs4Server::op_rename(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc) {
    if (!cs.saved_fh_set || !cs.current_fh_set)
        return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    std::string oldname = args.decode_string();
    std::string newname = args.decode_string();
    if (!is_valid_utf8(oldname) || !is_valid_utf8(newname))
        return Nfs4Stat::NFS4ERR_INVAL;

    // saved_fh = source dir, current_fh = target dir
    Fattr3 src_before, dst_before;
    vfs_.getattr(cs.saved_fh, src_before);
    vfs_.getattr(cs.current_fh, dst_before);

    NfsStat3 s = vfs_.rename(cs.saved_fh, oldname, cs.current_fh, newname);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    Fattr3 src_after, dst_after;
    vfs_.getattr(cs.saved_fh, src_after);
    vfs_.getattr(cs.current_fh, dst_after);

    auto make_change = [](const Fattr3& a) -> uint64_t {
        return (static_cast<uint64_t>(a.mtime.seconds) << 32) | a.mtime.nseconds;
    };

    // source change_info
    enc.encode_bool(false);
    enc.encode_uint64(make_change(src_before));
    enc.encode_uint64(make_change(src_after));

    // target change_info
    enc.encode_bool(false);
    enc.encode_uint64(make_change(dst_before));
    enc.encode_uint64(make_change(dst_after));

    return Nfs4Stat::NFS4_OK;
}

// RFC 7530 §16.31 - VERIFY / §16.14 - NVERIFY common logic
Nfs4Stat Nfs4Server::verify_common(CompoundState& cs, XdrDecoder& args, bool negate) {
    if (!cs.current_fh_set) return Nfs4Stat::NFS4ERR_NOFILEHANDLE;

    // Decode the client-supplied fattr4 (bitmap + opaque attr data)
    auto client_bm = decode_bitmap(args);
    auto client_attr_data = args.decode_opaque();

    // Get actual file attributes
    Fattr3 attr;
    NfsStat3 s = vfs_.getattr(cs.current_fh, attr);
    if (s != NfsStat3::NFS3_OK) return nfs3stat_to_nfs4stat(s);

    // Encode server's fattr4 using the same bitmap the client requested
    XdrEncoder server_enc;
    encode_fattr4(server_enc, client_bm, attr, cs.current_fh);

    // The encode_fattr4 output includes the result bitmap + opaque attr data.
    // We need to extract just the opaque attr data for comparison.
    // Re-decode the server-encoded fattr4 to get the attr data portion.
    XdrDecoder server_dec(server_enc.data().data(), server_enc.size());
    auto server_bm = decode_bitmap(server_dec);
    auto server_attr_data = server_dec.decode_opaque();

    bool match = (client_attr_data == server_attr_data);

    if (negate) {
        // NVERIFY: succeed if attrs DON'T match (so client can proceed)
        return match ? Nfs4Stat::NFS4ERR_SAME : Nfs4Stat::NFS4_OK;
    } else {
        // VERIFY: succeed if attrs DO match
        return match ? Nfs4Stat::NFS4_OK : Nfs4Stat::NFS4ERR_NOT_SAME;
    }
}

// RFC 7530 §16.31 - VERIFY
Nfs4Stat Nfs4Server::op_verify(CompoundState& cs, XdrDecoder& args, XdrEncoder&) {
    return verify_common(cs, args, false);
}

// RFC 7530 §16.14 - NVERIFY
Nfs4Stat Nfs4Server::op_nverify(CompoundState& cs, XdrDecoder& args, XdrEncoder&) {
    return verify_common(cs, args, true);
}

// RFC 7530 §16.5 - DELEGRETURN
Nfs4Stat Nfs4Server::op_delegreturn(CompoundState&, XdrDecoder& args, XdrEncoder&) {
    Nfs4StateId stateid;
    decode_stateid(args, stateid);
    return state_.delegreturn(stateid);
}

// RFC 7530 §16.4 - DELEGPURGE
Nfs4Stat Nfs4Server::op_delegpurge(CompoundState&, XdrDecoder& args, XdrEncoder&) {
    uint64_t clientid = args.decode_uint64();
    return state_.delegpurge(clientid);
}
