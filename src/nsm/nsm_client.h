#pragma once

#include "locking/lock_table.h"
#include <cstdint>
#include <mutex>
#include <set>
#include <string>

// NSM — Network Status Monitor (program 100024)
// Client-side implementation for NLM crash recovery.
// Registers with local rpc.statd to be notified when clients reboot.

constexpr uint32_t SM_PROGRAM = 100024;
constexpr uint32_t SM_VERSION = 1;
constexpr uint32_t SM_MON     = 2;
constexpr uint32_t SM_UNMON   = 3;
constexpr uint32_t SM_UNMON_ALL = 4;

class NsmClient {
public:
    NsmClient(ByteRangeLockTable& lock_table, std::mutex& lock_mu);

    // Monitor a client — call SM_MON on local rpc.statd.
    // Returns true if monitoring started, false if statd unreachable.
    bool monitor(const std::string& client_name,
                 const std::string& my_name,
                 uint32_t my_prog, uint32_t my_vers, uint32_t my_proc);

    // Stop monitoring a client.
    bool unmonitor(const std::string& client_name,
                   const std::string& my_name);

    // Stop monitoring all clients.
    bool unmonitor_all(const std::string& my_name);

    // Handle SM_NOTIFY callback — release all locks for the rebooted client.
    void handle_notify(const std::string& client_name);

    // Check if a client is being monitored.
    bool is_monitored(const std::string& client_name);

private:
    ByteRangeLockTable& lock_table_;
    std::mutex& lock_mu_;
    std::mutex nsm_mu_;
    std::set<std::string> monitored_;
};
