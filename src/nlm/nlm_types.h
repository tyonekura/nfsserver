#pragma once

#include "vfs/vfs.h"
#include <cstdint>
#include <string>
#include <vector>

// NLM v4 — Network Lock Manager for NFSv3
// Based on the NLM protocol (program 100021, version 4)

constexpr uint32_t NLM_PROGRAM = 100021;
constexpr uint32_t NLM_V4      = 4;

// Synchronous procedures
constexpr uint32_t NLMPROC4_NULL         = 0;
constexpr uint32_t NLMPROC4_TEST         = 1;
constexpr uint32_t NLMPROC4_LOCK         = 2;
constexpr uint32_t NLMPROC4_CANCEL       = 3;
constexpr uint32_t NLMPROC4_UNLOCK       = 4;
// Async MSG variants (7-12) not implemented — sync-only mode
constexpr uint32_t NLMPROC4_FREE_ALL     = 23;

// NLM status codes
enum class NlmStat : uint32_t {
    LCK_GRANTED          = 0,
    LCK_DENIED           = 1,
    LCK_DENIED_NOLOCKS   = 2,
    LCK_BLOCKED          = 3,
    LCK_DENIED_GRACE_PERIOD = 4,
    LCK_DEADLCK          = 5,
};

// nlm4_lock — describes a lock request
struct NlmLock {
    std::string caller_name;       // client hostname
    FileHandle fh;                 // fh3
    std::vector<uint8_t> oh;       // owner handle
    uint32_t svid = 0;            // server-verifier ID (typically process ID)
    uint64_t offset = 0;
    uint64_t length = 0;          // 0 = to EOF (NLM convention)
};

// nlm4_holder — describes who holds a conflicting lock
struct NlmHolder {
    bool exclusive = false;
    uint32_t svid = 0;
    std::vector<uint8_t> oh;
    uint64_t offset = 0;
    uint64_t length = 0;
};
