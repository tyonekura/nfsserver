#include <gtest/gtest.h>
#include "vfs/local_fs.h"
#include "nfs/nfs_types.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

class LocalFsTest : public ::testing::Test {
protected:
    std::string tmpdir_;
    std::unique_ptr<LocalFs> fs_;

    void SetUp() override {
        char tmpl[] = "/tmp/nfs_test_XXXXXX";
        char* dir = mkdtemp(tmpl);
        ASSERT_NE(dir, nullptr);
        tmpdir_ = dir;
        fs_ = std::make_unique<LocalFs>(tmpdir_);
    }

    void TearDown() override {
        // Clean up tmpdir recursively
        std::string cmd = "rm -rf " + tmpdir_;
        system(cmd.c_str());
    }

    FileHandle root_fh() {
        FileHandle fh;
        fs_->get_root_fh("/", fh);
        return fh;
    }
};

TEST_F(LocalFsTest, GetRootFh) {
    FileHandle fh;
    EXPECT_EQ(fs_->get_root_fh("/", fh), NfsStat3::NFS3_OK);
    EXPECT_GT(fh.len, 0u);
}

TEST_F(LocalFsTest, GetAttrRootDir) {
    FileHandle fh = root_fh();
    Fattr3 attr;
    EXPECT_EQ(fs_->getattr(fh, attr), NfsStat3::NFS3_OK);
    EXPECT_EQ(attr.type, Ftype3::NF3DIR);
}

TEST_F(LocalFsTest, CreateAndReadFile) {
    FileHandle rfh = root_fh();
    FileHandle file_fh;
    Fattr3 attr;
    EXPECT_EQ(fs_->create(rfh, "test.txt", 0644, file_fh, attr), NfsStat3::NFS3_OK);

    const char msg[] = "hello nfs";
    uint32_t written = 0;
    EXPECT_EQ(fs_->write(file_fh, 0, reinterpret_cast<const uint8_t*>(msg),
                          sizeof(msg) - 1, written), NfsStat3::NFS3_OK);
    EXPECT_EQ(written, sizeof(msg) - 1);

    std::vector<uint8_t> data;
    bool eof = false;
    EXPECT_EQ(fs_->read(file_fh, 0, 64, data, eof), NfsStat3::NFS3_OK);
    EXPECT_EQ(data.size(), sizeof(msg) - 1);
    EXPECT_TRUE(eof);
    EXPECT_EQ(std::string(data.begin(), data.end()), "hello nfs");
}

TEST_F(LocalFsTest, StaleHandleAfterRemove) {
    FileHandle rfh = root_fh();
    FileHandle file_fh;
    Fattr3 attr;
    fs_->create(rfh, "stale.txt", 0644, file_fh, attr);
    EXPECT_EQ(fs_->remove(rfh, "stale.txt"), NfsStat3::NFS3_OK);

    // After removal the handle should be evicted from cache
    Fattr3 attr2;
    NfsStat3 status = fs_->getattr(file_fh, attr2);
    EXPECT_EQ(status, NfsStat3::NFS3ERR_STALE);
}

TEST_F(LocalFsTest, RenameUpdatesCache) {
    FileHandle rfh = root_fh();
    FileHandle file_fh;
    Fattr3 attr;
    fs_->create(rfh, "old.txt", 0644, file_fh, attr);

    EXPECT_EQ(fs_->rename(rfh, "old.txt", rfh, "new.txt"), NfsStat3::NFS3_OK);

    // Handle should still be valid after rename
    Fattr3 attr2;
    EXPECT_EQ(fs_->getattr(file_fh, attr2), NfsStat3::NFS3_OK);
}

TEST_F(LocalFsTest, RmdirEvictsHandle) {
    FileHandle rfh = root_fh();
    FileHandle dir_fh;
    Fattr3 attr;
    fs_->mkdir(rfh, "subdir", 0755, dir_fh, attr);

    EXPECT_EQ(fs_->rmdir(rfh, "subdir"), NfsStat3::NFS3_OK);

    Fattr3 attr2;
    EXPECT_EQ(fs_->getattr(dir_fh, attr2), NfsStat3::NFS3ERR_STALE);
}

TEST_F(LocalFsTest, AccessCheckPermissions) {
    FileHandle rfh = root_fh();
    FileHandle file_fh;
    Fattr3 attr;
    fs_->create(rfh, "readable.txt", 0444, file_fh, attr);

    uint32_t granted = 0;
    EXPECT_EQ(fs_->access(file_fh, ACCESS3_READ | ACCESS3_MODIFY, granted), NfsStat3::NFS3_OK);
    EXPECT_TRUE(granted & ACCESS3_READ);
    // 0444 has no write bits, so MODIFY should not be granted
    EXPECT_FALSE(granted & ACCESS3_MODIFY);
}

TEST_F(LocalFsTest, SetAttrWithMtime) {
    FileHandle rfh = root_fh();
    FileHandle file_fh;
    Fattr3 attr;
    fs_->create(rfh, "timed.txt", 0644, file_fh, attr);

    NfsTimeSet atime;
    NfsTimeSet mtime;
    mtime.how = NfsTimeSet::How::SET_TO_CLIENT_TIME;
    mtime.time.seconds = 1000000;
    mtime.time.nseconds = 0;

    EXPECT_EQ(fs_->setattr(file_fh, UINT32_MAX, UINT32_MAX, UINT32_MAX,
                             UINT64_MAX, atime, mtime), NfsStat3::NFS3_OK);

    Fattr3 attr2;
    EXPECT_EQ(fs_->getattr(file_fh, attr2), NfsStat3::NFS3_OK);
    EXPECT_EQ(attr2.mtime.seconds, 1000000u);
}

TEST_F(LocalFsTest, LookupNonexistent) {
    FileHandle rfh = root_fh();
    FileHandle out_fh;
    Fattr3 attr;
    EXPECT_EQ(fs_->lookup(rfh, "nonexistent", out_fh, attr), NfsStat3::NFS3ERR_NOENT);
}

TEST_F(LocalFsTest, Readdir) {
    FileHandle rfh = root_fh();
    FileHandle fh;
    Fattr3 attr;
    fs_->create(rfh, "file1.txt", 0644, fh, attr);
    fs_->create(rfh, "file2.txt", 0644, fh, attr);

    std::vector<DirEntry> entries;
    bool eof = false;
    EXPECT_EQ(fs_->readdir(rfh, 0, 100, entries, eof), NfsStat3::NFS3_OK);
    EXPECT_TRUE(eof);
    // Should have at least ".", "..", "file1.txt", "file2.txt"
    EXPECT_GE(entries.size(), 4u);
}
