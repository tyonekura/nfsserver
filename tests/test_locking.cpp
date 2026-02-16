#include <gtest/gtest.h>
#include <cstring>
#include "locking/lock_table.h"

static FileHandle make_fh(uint64_t id) {
    FileHandle fh{};
    std::memcpy(fh.data, &id, sizeof(id));
    fh.len = sizeof(id);
    return fh;
}

TEST(LockTable, RangesOverlap) {
    // Overlapping
    EXPECT_TRUE(ByteRangeLockTable::ranges_overlap(0, 100, 50, 100));
    EXPECT_TRUE(ByteRangeLockTable::ranges_overlap(50, 100, 0, 100));
    // Adjacent (no overlap)
    EXPECT_FALSE(ByteRangeLockTable::ranges_overlap(0, 50, 50, 50));
    // Contained
    EXPECT_TRUE(ByteRangeLockTable::ranges_overlap(0, 100, 10, 20));
    // EOF range
    EXPECT_TRUE(ByteRangeLockTable::ranges_overlap(0, UINT64_MAX, 100, 50));
    EXPECT_TRUE(ByteRangeLockTable::ranges_overlap(100, 50, 0, UINT64_MAX));
    // No overlap
    EXPECT_FALSE(ByteRangeLockTable::ranges_overlap(0, 10, 20, 10));
}

TEST(LockTable, AcquireAndTest) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    // Acquire an exclusive lock
    EXPECT_TRUE(table.acquire(fh, "owner1", true, 0, 100, conflict));

    // Another owner should see conflict
    EXPECT_TRUE(table.test(fh, "owner2", true, 50, 50, conflict));
    EXPECT_EQ(conflict.offset, 0u);
    EXPECT_EQ(conflict.length, 100u);
    EXPECT_TRUE(conflict.exclusive);
    EXPECT_EQ(conflict.owner, "owner1");
}

TEST(LockTable, ReadReadNoConflict) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    EXPECT_TRUE(table.acquire(fh, "owner1", false, 0, 100, conflict));
    // Another read lock on same range should succeed
    EXPECT_TRUE(table.acquire(fh, "owner2", false, 0, 100, conflict));
}

TEST(LockTable, ReadWriteConflict) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    EXPECT_TRUE(table.acquire(fh, "owner1", false, 0, 100, conflict));
    // Write lock should conflict with read
    EXPECT_FALSE(table.acquire(fh, "owner2", true, 50, 50, conflict));
}

TEST(LockTable, SameOwnerNoConflict) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    EXPECT_TRUE(table.acquire(fh, "owner1", true, 0, 100, conflict));
    // Same owner can acquire overlapping lock
    EXPECT_TRUE(table.acquire(fh, "owner1", true, 50, 100, conflict));
}

TEST(LockTable, ReleaseAndRelock) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    EXPECT_TRUE(table.acquire(fh, "owner1", true, 0, 100, conflict));
    EXPECT_FALSE(table.acquire(fh, "owner2", true, 0, 100, conflict));

    table.release(fh, "owner1", 0, 100);
    // Now owner2 should succeed
    EXPECT_TRUE(table.acquire(fh, "owner2", true, 0, 100, conflict));
}

TEST(LockTable, RangeSplitting) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    // Lock 0-100
    EXPECT_TRUE(table.acquire(fh, "owner1", true, 0, 100, conflict));
    // Unlock 25-75 (splits into 0-25 and 75-100)
    table.release(fh, "owner1", 25, 50);

    // Middle should be free for another owner
    EXPECT_TRUE(table.acquire(fh, "owner2", true, 30, 40, conflict));
    // Left remnant still locked
    EXPECT_FALSE(table.acquire(fh, "owner2", true, 0, 25, conflict));
    // Right remnant still locked
    EXPECT_FALSE(table.acquire(fh, "owner2", true, 75, 25, conflict));
}

TEST(LockTable, ReleaseAll) {
    ByteRangeLockTable table;
    FileHandle fh1 = make_fh(1);
    FileHandle fh2 = make_fh(2);
    LockConflict conflict;

    table.acquire(fh1, "owner1", true, 0, 100, conflict);
    table.acquire(fh2, "owner1", true, 0, 100, conflict);
    table.acquire(fh1, "owner2", false, 200, 100, conflict);

    table.release_all("owner1");

    // owner1's locks gone
    EXPECT_TRUE(table.acquire(fh1, "owner3", true, 0, 100, conflict));
    EXPECT_TRUE(table.acquire(fh2, "owner3", true, 0, 100, conflict));
    // owner2's lock still there
    EXPECT_FALSE(table.acquire(fh1, "owner3", true, 200, 100, conflict));
}

TEST(LockTable, ReleaseAllMatching) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    table.acquire(fh, "nlm:host1:100", true, 0, 50, conflict);
    table.acquire(fh, "nlm:host1:200", true, 50, 50, conflict);
    table.acquire(fh, "nlm:host2:100", true, 100, 50, conflict);

    // Release all nlm:host1:* locks
    table.release_all_matching("nlm:host1:");

    // host1 locks gone
    EXPECT_TRUE(table.acquire(fh, "other", true, 0, 100, conflict));
    // host2 lock still there
    EXPECT_FALSE(table.acquire(fh, "other", true, 100, 50, conflict));
}

TEST(LockTable, HasLocks) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    EXPECT_FALSE(table.has_locks(fh, "owner1"));
    table.acquire(fh, "owner1", true, 0, 100, conflict);
    EXPECT_TRUE(table.has_locks(fh, "owner1"));
    table.release(fh, "owner1", 0, 100);
    EXPECT_FALSE(table.has_locks(fh, "owner1"));
}

TEST(LockTable, CrossProtocol) {
    ByteRangeLockTable table;
    FileHandle fh = make_fh(1);
    LockConflict conflict;

    // NFSv4 lock
    EXPECT_TRUE(table.acquire(fh, "v4:1:abcd", true, 0, 100, conflict));
    // NLM lock on same range should conflict
    EXPECT_FALSE(table.acquire(fh, "nlm:host1:100", true, 0, 100, conflict));
    EXPECT_EQ(conflict.owner, "v4:1:abcd");
}

TEST(LockTable, DifferentFiles) {
    ByteRangeLockTable table;
    FileHandle fh1 = make_fh(1);
    FileHandle fh2 = make_fh(2);
    LockConflict conflict;

    EXPECT_TRUE(table.acquire(fh1, "owner1", true, 0, 100, conflict));
    // Different file should not conflict
    EXPECT_TRUE(table.acquire(fh2, "owner2", true, 0, 100, conflict));
}

TEST(LockTable, ReleaseAllForFile) {
    ByteRangeLockTable table;
    FileHandle fh1 = make_fh(1);
    FileHandle fh2 = make_fh(2);
    LockConflict conflict;

    table.acquire(fh1, "owner1", true, 0, 100, conflict);
    table.acquire(fh2, "owner1", true, 0, 100, conflict);

    table.release_all_for_file(fh1, "owner1");

    // fh1 lock gone
    EXPECT_TRUE(table.acquire(fh1, "owner2", true, 0, 100, conflict));
    // fh2 lock still there
    EXPECT_FALSE(table.acquire(fh2, "owner2", true, 0, 100, conflict));
}
