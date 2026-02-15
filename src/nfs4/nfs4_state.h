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

// RFC 7530 §16.10 - Lock owner identity
struct Nfs4LockOwner {
    uint64_t clientid = 0;
    std::vector<uint8_t> owner;
    bool operator==(const Nfs4LockOwner& o) const {
        return clientid == o.clientid && owner == o.owner;
    }
};

// RFC 7530 §16.10 - Byte-range lock
struct Nfs4LockRange {
    uint64_t offset = 0;
    uint64_t length = 0;       // UINT64_MAX = to EOF
    uint32_t locktype = 0;     // READ_LT or WRITE_LT
};

// RFC 7530 §16.10 - LOCK4denied response
struct Nfs4LockDenied {
    uint64_t offset = 0;
    uint64_t length = 0;
    uint32_t locktype = 0;
    Nfs4LockOwner owner;
};

// All lock state for one lock_owner on one file
struct Nfs4LockState {
    Nfs4StateId stateid;
    Nfs4LockOwner lock_owner;
    FileHandle fh;
    uint64_t clientid = 0;
    uint8_t open_stateid_other[12] = {};  // backlink for cleanup on CLOSE
    uint32_t lock_seqid = 0;
    std::vector<Nfs4LockRange> ranges;
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

    // RFC 7530 §16.19 - OPEN_DOWNGRADE
    Nfs4Stat open_downgrade(const Nfs4StateId& stateid, uint32_t seqid,
                             uint32_t access, uint32_t deny,
                             Nfs4StateId& out_stateid);

    // RFC 7530 §16.27 - RENEW
    Nfs4Stat renew(uint64_t clientid);

    // Validate a stateid for READ/WRITE access
    Nfs4Stat validate_stateid(const Nfs4StateId& stateid, uint32_t required_access);

    // Check if stateid is a special (anonymous or bypass) stateid
    static bool is_special_stateid(const Nfs4StateId& sid);

    // RFC 7530 §16.10 - LOCK (new lock_owner)
    Nfs4Stat lock_new(uint64_t clientid,
                      const Nfs4StateId& open_stateid,
                      uint32_t open_seqid,
                      const Nfs4LockOwner& lock_owner,
                      uint32_t lock_seqid,
                      const FileHandle& fh,
                      uint32_t locktype,
                      uint64_t offset, uint64_t length,
                      Nfs4StateId& out_stateid,
                      Nfs4LockDenied& denied);

    // RFC 7530 §16.10 - LOCK (existing lock_stateid)
    Nfs4Stat lock_existing(const Nfs4StateId& lock_stateid,
                           uint32_t lock_seqid,
                           uint32_t locktype,
                           uint64_t offset, uint64_t length,
                           Nfs4StateId& out_stateid,
                           Nfs4LockDenied& denied);

    // RFC 7530 §16.11 - LOCKT
    Nfs4Stat lock_test(const FileHandle& fh,
                       uint32_t locktype,
                       uint64_t offset, uint64_t length,
                       const Nfs4LockOwner& lock_owner,
                       Nfs4LockDenied& denied);

    // RFC 7530 §16.12 - LOCKU
    Nfs4Stat lock_unlock(const Nfs4StateId& lock_stateid,
                         uint32_t seqid,
                         uint64_t offset, uint64_t length,
                         Nfs4StateId& out_stateid);

    // RFC 7530 §16.26 - RELEASE_LOCKOWNER
    Nfs4Stat release_lock_owner(const Nfs4LockOwner& lock_owner);

private:
    // Lookup open state by stateid.other bytes
    Nfs4OpenState* find_open_state(const Nfs4StateId& sid);

    // Lookup lock state by stateid.other bytes
    Nfs4LockState* find_lock_state(const Nfs4StateId& sid);
    Nfs4LockState* find_lock_state_by_owner(const Nfs4LockOwner& owner, const FileHandle& fh);
    bool check_lock_conflict(const FileHandle& fh, const Nfs4LockOwner& requester,
                             uint32_t locktype, uint64_t offset, uint64_t length,
                             Nfs4LockDenied& denied);
    void remove_lock_range(Nfs4LockState& ls, uint64_t offset, uint64_t length);

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
    std::vector<Nfs4LockState> lock_states_;

    std::atomic<bool> reaper_running_{true};
    std::thread reaper_thread_;
};
