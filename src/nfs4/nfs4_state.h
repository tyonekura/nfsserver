#pragma once

#include "nfs4/nfs4_types.h"
#include "vfs/vfs.h"
#include <array>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

// RFC 7530 §3.2 - NFSv4 client and open state management

struct Nfs4Client {
    uint64_t clientid = 0;
    uint8_t verifier[8] = {};
    uint8_t confirm_verifier[8] = {};
    std::vector<uint8_t> client_id;    // nfs_client_id4.id (opaque)
    bool confirmed = false;
    std::chrono::steady_clock::time_point last_renewed;
};

struct Nfs4OpenState {
    Nfs4StateId stateid;
    uint64_t clientid = 0;
    FileHandle fh;
    uint32_t access = 0;              // OPEN4_SHARE_ACCESS_*
    uint32_t deny = 0;
    std::vector<uint8_t> owner;       // open_owner4.owner
    uint32_t open_seqid = 0;         // last seqid used by owner
    bool confirmed = false;           // needs OPEN_CONFIRM
};

class Nfs4StateManager {
public:
    Nfs4StateManager();
    ~Nfs4StateManager();

    // RFC 7530 §16.33 - SETCLIENTID
    // Returns {clientid, confirm_verifier}
    std::pair<uint64_t, std::array<uint8_t, 8>>
        set_clientid(const uint8_t verifier[8],
                     const std::vector<uint8_t>& client_id);

    // RFC 7530 §16.34 - SETCLIENTID_CONFIRM
    Nfs4Stat confirm_clientid(uint64_t clientid,
                               const uint8_t confirm[8]);

    // RFC 7530 §16.16 - OPEN
    Nfs4Stat open_file(uint64_t clientid,
                       const std::vector<uint8_t>& owner,
                       uint32_t seqid,
                       const FileHandle& fh,
                       uint32_t access, uint32_t deny,
                       Nfs4StateId& out_stateid,
                       bool& needs_confirm);

    // RFC 7530 §16.18 - OPEN_CONFIRM
    Nfs4Stat confirm_open(const Nfs4StateId& stateid, uint32_t seqid,
                           Nfs4StateId& out_stateid);

    // RFC 7530 §16.4 - CLOSE
    Nfs4Stat close_file(const Nfs4StateId& stateid, uint32_t seqid,
                         Nfs4StateId& out_stateid);

    // RFC 7530 §16.27 - RENEW
    Nfs4Stat renew(uint64_t clientid);

    // Validate a stateid for READ/WRITE access
    Nfs4Stat validate_stateid(const Nfs4StateId& stateid, uint32_t required_access);

    // Check if stateid is a special (anonymous or bypass) stateid
    static bool is_special_stateid(const Nfs4StateId& sid);

private:
    // Lookup open state by stateid.other bytes
    Nfs4OpenState* find_open_state(const Nfs4StateId& sid);

    // Generate a unique stateid.other
    void gen_stateid_other(uint8_t out[12]);

    // RFC 7530 §9.6 - Lease expiry: remove expired clients and their open state
    void expire_clients();
    void reaper_loop();

    std::mutex mu_;
    uint64_t next_clientid_ = 1;
    uint64_t next_state_counter_ = 1;
    std::map<uint64_t, Nfs4Client> clients_;                       // clientid -> client
    std::map<std::vector<uint8_t>, uint64_t> client_id_to_clientid_; // nfs_client_id4 -> clientid
    std::vector<Nfs4OpenState> open_states_;

    std::atomic<bool> reaper_running_{true};
    std::thread reaper_thread_;
};
