#pragma once

#include "vfs/vfs.h"
#include <cstdint>
#include <string>
#include <vector>

// Protocol-agnostic byte-range lock table.
// Used by both NFSv4 state manager and NLM (NFSv3 locking).
// No internal mutex — caller provides synchronization.

using LockOwnerKey = std::string;

struct LockRange {
    uint64_t offset = 0;
    uint64_t length = 0;  // UINT64_MAX = to EOF
    bool exclusive = false;
};

struct LockConflict {
    uint64_t offset = 0;
    uint64_t length = 0;
    bool exclusive = false;
    LockOwnerKey owner;
};

struct LockEntry {
    LockOwnerKey owner;
    FileHandle fh;
    std::vector<LockRange> ranges;
};

class ByteRangeLockTable {
public:
    // Test for conflict (does not modify state)
    bool test(const FileHandle& fh, const LockOwnerKey& requester,
              bool exclusive, uint64_t offset, uint64_t length,
              LockConflict& conflict);

    // Acquire lock (returns false on conflict)
    bool acquire(const FileHandle& fh, const LockOwnerKey& owner,
                 bool exclusive, uint64_t offset, uint64_t length,
                 LockConflict& conflict);

    // Release a range (may split existing ranges)
    void release(const FileHandle& fh, const LockOwnerKey& owner,
                 uint64_t offset, uint64_t length);

    // Drop all locks for an owner
    void release_all(const LockOwnerKey& owner);

    // Drop all locks matching an owner prefix (e.g., "nlm:hostname:")
    void release_all_matching(const std::string& prefix);

    // Drop all locks for a file+owner
    void release_all_for_file(const FileHandle& fh, const LockOwnerKey& owner);

    // Check if an owner holds any locks on a file
    bool has_locks(const FileHandle& fh, const LockOwnerKey& owner);

    static bool ranges_overlap(uint64_t o1, uint64_t l1, uint64_t o2, uint64_t l2);

private:
    std::vector<LockEntry> entries_;

    LockEntry* find_entry(const FileHandle& fh, const LockOwnerKey& owner);
    void remove_range(LockEntry& entry, uint64_t offset, uint64_t length);
    void cleanup_empty();
};
