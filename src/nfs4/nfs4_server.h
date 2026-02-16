#pragma once

#include "rpc/rpc_server.h"
#include "vfs/vfs.h"
#include "nfs4/nfs4_types.h"
#include "nfs4/nfs4_state.h"
#include <atomic>
#include <map>
#include <string>

// RFC 7530 - NFS Version 4 Protocol Server

// Per-COMPOUND request state
struct CompoundState {
    FileHandle current_fh;
    bool current_fh_set = false;
    FileHandle saved_fh;
    bool saved_fh_set = false;
    // AUTH_SYS credentials from RPC call header
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::vector<uint32_t> gids;
};

class Nfs4Server {
public:
    Nfs4Server(Vfs& vfs, const std::string& export_root);

    RpcProgramHandlers get_handlers();

private:
    // RFC 7530 §16.1 - Procedure 0: NULL
    void proc_null(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    // RFC 7530 §16.2 - Procedure 1: COMPOUND
    void proc_compound(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);

    // Operation handler type: returns status, encodes result into enc
    using OpHandler = Nfs4Stat (Nfs4Server::*)(CompoundState& cs,
                                                XdrDecoder& args,
                                                XdrEncoder& enc);

    // RFC 7530 §16 - Individual operation handlers
    Nfs4Stat op_access(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_close(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_commit(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_create(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_getattr(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_getfh(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_link(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_lock(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_lockt(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_locku(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_lookup(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_lookupp(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_open(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_open_confirm(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_open_downgrade(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_putfh(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_putrootfh(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_read(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_readdir(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_readlink(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_remove(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_rename(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_renew(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_restorefh(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_savefh(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_secinfo(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_setattr(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_setclientid(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_setclientid_confirm(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_verify(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_nverify(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_release_lockowner(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_write(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_delegreturn(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);
    Nfs4Stat op_delegpurge(CompoundState& cs, XdrDecoder& args, XdrEncoder& enc);

    // Helpers
    Nfs4Stat verify_common(CompoundState& cs, XdrDecoder& args, bool negate);
    void encode_change_info(XdrEncoder& enc, const FileHandle& dir_fh);
    Nfs4Stat decode_stateid(XdrDecoder& args, Nfs4StateId& sid);

    Vfs& vfs_;
    std::string export_root_;
    FileHandle root_fh_;
    Nfs4StateManager state_;
    std::map<uint32_t, OpHandler> op_handlers_;
    uint64_t write_verifier_ = 0;
    std::atomic<uint32_t> next_cb_xid_{1};
};
