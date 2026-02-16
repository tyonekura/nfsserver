#include "locking/lock_table.h"
#include <algorithm>

bool ByteRangeLockTable::ranges_overlap(uint64_t o1, uint64_t l1,
                                         uint64_t o2, uint64_t l2) {
    uint64_t end1 = (l1 == UINT64_MAX) ? UINT64_MAX : o1 + l1;
    uint64_t end2 = (l2 == UINT64_MAX) ? UINT64_MAX : o2 + l2;
    return o1 < end2 && o2 < end1;
}

LockEntry* ByteRangeLockTable::find_entry(const FileHandle& fh,
                                           const LockOwnerKey& owner) {
    for (auto& e : entries_)
        if (e.fh == fh && e.owner == owner) return &e;
    return nullptr;
}

void ByteRangeLockTable::remove_range(LockEntry& entry,
                                       uint64_t offset, uint64_t length) {
    uint64_t rem_end = (length == UINT64_MAX) ? UINT64_MAX : offset + length;
    std::vector<LockRange> new_ranges;

    for (const auto& r : entry.ranges) {
        uint64_t r_end = (r.length == UINT64_MAX) ? UINT64_MAX : r.offset + r.length;

        if (!ranges_overlap(offset, length, r.offset, r.length)) {
            new_ranges.push_back(r);
            continue;
        }

        // Left remnant
        if (r.offset < offset) {
            LockRange left = r;
            left.length = offset - r.offset;
            new_ranges.push_back(left);
        }

        // Right remnant
        if (r_end > rem_end && rem_end != UINT64_MAX) {
            LockRange right = r;
            right.offset = rem_end;
            right.length = (r.length == UINT64_MAX) ? UINT64_MAX : r_end - rem_end;
            new_ranges.push_back(right);
        }
    }

    entry.ranges = std::move(new_ranges);
}

void ByteRangeLockTable::cleanup_empty() {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [](const LockEntry& e) { return e.ranges.empty(); }),
        entries_.end());
}

bool ByteRangeLockTable::test(const FileHandle& fh, const LockOwnerKey& requester,
                               bool exclusive, uint64_t offset, uint64_t length,
                               LockConflict& conflict) {
    for (const auto& e : entries_) {
        if (!(e.fh == fh)) continue;
        if (e.owner == requester) continue;
        for (const auto& r : e.ranges) {
            if (!exclusive && !r.exclusive) continue;  // read-read OK
            if (ranges_overlap(offset, length, r.offset, r.length)) {
                conflict.offset = r.offset;
                conflict.length = r.length;
                conflict.exclusive = r.exclusive;
                conflict.owner = e.owner;
                return true;
            }
        }
    }
    return false;
}

bool ByteRangeLockTable::acquire(const FileHandle& fh, const LockOwnerKey& owner,
                                  bool exclusive, uint64_t offset, uint64_t length,
                                  LockConflict& conflict) {
    if (test(fh, owner, exclusive, offset, length, conflict))
        return false;

    auto* entry = find_entry(fh, owner);
    if (!entry) {
        entries_.push_back({owner, fh, {}});
        entry = &entries_.back();
    }
    entry->ranges.push_back({offset, length, exclusive});
    return true;
}

void ByteRangeLockTable::release(const FileHandle& fh, const LockOwnerKey& owner,
                                  uint64_t offset, uint64_t length) {
    auto* entry = find_entry(fh, owner);
    if (!entry) return;
    remove_range(*entry, offset, length);
    cleanup_empty();
}

void ByteRangeLockTable::release_all(const LockOwnerKey& owner) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const LockEntry& e) { return e.owner == owner; }),
        entries_.end());
}

void ByteRangeLockTable::release_all_matching(const std::string& prefix) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const LockEntry& e) {
                           return e.owner.compare(0, prefix.size(), prefix) == 0;
                       }),
        entries_.end());
}

bool ByteRangeLockTable::has_locks(const FileHandle& fh,
                                    const LockOwnerKey& owner) {
    auto* entry = find_entry(fh, owner);
    return entry != nullptr && !entry->ranges.empty();
}

void ByteRangeLockTable::release_all_for_file(const FileHandle& fh,
                                               const LockOwnerKey& owner) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const LockEntry& e) {
                           return e.fh == fh && e.owner == owner;
                       }),
        entries_.end());
}
