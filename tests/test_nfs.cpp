#include <gtest/gtest.h>
#include "vfs/vfs.h"
#include "nfs/nfs_types.h"

TEST(NfsTypes, FileHandleComparison) {
    FileHandle a, b;
    a.len = 4;
    a.data[0] = 1; a.data[1] = 2; a.data[2] = 3; a.data[3] = 4;
    b = a;
    EXPECT_TRUE(a == b);

    b.data[3] = 5;
    EXPECT_FALSE(a == b);
    EXPECT_TRUE(a < b);
}

TEST(NfsTypes, ProcedureConstants) {
    EXPECT_EQ(NFSPROC3_NULL, 0u);
    EXPECT_EQ(NFSPROC3_GETATTR, 1u);
    EXPECT_EQ(NFSPROC3_READ, 6u);
    EXPECT_EQ(NFSPROC3_WRITE, 7u);
    EXPECT_EQ(NFSPROC3_READDIR, 16u);
    EXPECT_EQ(NFSPROC3_COMMIT, 21u);
}

TEST(NfsTypes, NfsStatValues) {
    EXPECT_EQ(static_cast<uint32_t>(NfsStat3::NFS3_OK), 0u);
    EXPECT_EQ(static_cast<uint32_t>(NfsStat3::NFS3ERR_NOENT), 2u);
    EXPECT_EQ(static_cast<uint32_t>(NfsStat3::NFS3ERR_STALE), 70u);
}
