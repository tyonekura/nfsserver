#include <gtest/gtest.h>
#include "vfs/vfs.h"
#include "vfs/local_fs.h"
#include "nfs/nfs_types.h"
#include "nfs/nfs_server.h"

#include <cstdlib>
#include <unistd.h>

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

// Helper: decode fattr3 from reply, skipping post_op_attr bool
static Fattr3 decode_fattr3(XdrDecoder& dec) {
    Fattr3 attr;
    attr.type = static_cast<Ftype3>(dec.decode_uint32());
    attr.mode = dec.decode_uint32();
    attr.nlink = dec.decode_uint32();
    attr.uid = dec.decode_uint32();
    attr.gid = dec.decode_uint32();
    attr.size = dec.decode_uint64();
    attr.used = dec.decode_uint64();
    attr.rdev_major = dec.decode_uint32();
    attr.rdev_minor = dec.decode_uint32();
    attr.fsid = dec.decode_uint64();
    attr.fileid = dec.decode_uint64();
    attr.atime.seconds = dec.decode_uint32();
    attr.atime.nseconds = dec.decode_uint32();
    attr.mtime.seconds = dec.decode_uint32();
    attr.mtime.nseconds = dec.decode_uint32();
    attr.ctime.seconds = dec.decode_uint32();
    attr.ctime.nseconds = dec.decode_uint32();
    return attr;
}

class NfsProcTest : public ::testing::Test {
protected:
    std::string tmpdir_;
    std::unique_ptr<LocalFs> fs_;
    std::unique_ptr<NfsServer> nfs_;
    FileHandle root_fh_;

    void SetUp() override {
        char tmpl[] = "/tmp/nfs_proc_XXXXXX";
        char* dir = mkdtemp(tmpl);
        ASSERT_NE(dir, nullptr);
        tmpdir_ = dir;
        fs_ = std::make_unique<LocalFs>(tmpdir_);
        nfs_ = std::make_unique<NfsServer>(*fs_);
        fs_->get_root_fh("/", root_fh_);
    }

    void TearDown() override {
        std::string cmd = "rm -rf " + tmpdir_;
        system(cmd.c_str());
    }

    // Encode a file handle as variable-length opaque (for procedure args)
    void encode_fh(XdrEncoder& enc, const FileHandle& fh) {
        enc.encode_opaque(fh.data, fh.len);
    }

    RpcCallHeader make_call() {
        RpcCallHeader c;
        c.xid = 1;
        c.rpc_version = 2;
        c.program = NFS_PROGRAM;
        c.version = NFS_V3;
        return c;
    }
};

TEST_F(NfsProcTest, FsInfoRtmult) {
    XdrEncoder args;
    encode_fh(args, root_fh_);
    XdrDecoder dec(args.data().data(), args.size());
    XdrEncoder reply;

    auto call = make_call();
    auto handlers = nfs_->get_handlers();
    handlers.procedures[NFSPROC3_FSINFO](call, dec, reply);

    XdrDecoder rdec(reply.data().data(), reply.size());
    uint32_t status = rdec.decode_uint32();
    EXPECT_EQ(status, 0u); // NFS3_OK

    // Skip post_op_attr
    if (rdec.decode_bool()) decode_fattr3(rdec);

    uint32_t rtmax = rdec.decode_uint32();
    uint32_t rtpref = rdec.decode_uint32();
    uint32_t rtmult = rdec.decode_uint32();
    uint32_t wtmax = rdec.decode_uint32();
    uint32_t wtpref = rdec.decode_uint32();
    uint32_t wtmult = rdec.decode_uint32();

    EXPECT_EQ(rtmult, 4096u);
    EXPECT_EQ(wtmult, 4096u);
    EXPECT_GT(rtmax, 0u);
    EXPECT_GT(rtpref, 0u);
    EXPECT_GT(wtmax, 0u);
    EXPECT_GT(wtpref, 0u);
}

TEST_F(NfsProcTest, PathConfCaseInsensitive) {
    XdrEncoder args;
    encode_fh(args, root_fh_);
    XdrDecoder dec(args.data().data(), args.size());
    XdrEncoder reply;

    auto call = make_call();
    auto handlers = nfs_->get_handlers();
    handlers.procedures[NFSPROC3_PATHCONF](call, dec, reply);

    XdrDecoder rdec(reply.data().data(), reply.size());
    uint32_t status = rdec.decode_uint32();
    EXPECT_EQ(status, 0u);

    // Skip post_op_attr
    if (rdec.decode_bool()) decode_fattr3(rdec);

    rdec.decode_uint32(); // linkmax
    rdec.decode_uint32(); // name_max
    rdec.decode_bool();   // no_trunc
    rdec.decode_bool();   // chown_restricted
    bool case_insensitive = rdec.decode_bool();
    EXPECT_FALSE(case_insensitive);
}

TEST_F(NfsProcTest, SetAttrGuardMismatch) {
    // Create a file
    FileHandle file_fh;
    Fattr3 attr;
    fs_->create(root_fh_, "guard_test.txt", 0644, file_fh, attr);

    // Build SETATTR args with a mismatched guard
    XdrEncoder args;
    encode_fh(args, file_fh);
    // sattr3: don't change anything
    args.encode_bool(false); // mode
    args.encode_bool(false); // uid
    args.encode_bool(false); // gid
    args.encode_bool(false); // size
    args.encode_uint32(0);   // atime: DONT_CHANGE
    args.encode_uint32(0);   // mtime: DONT_CHANGE
    // sattrguard3: check = true, with wrong ctime
    args.encode_bool(true);
    args.encode_uint32(99999); // wrong ctime seconds
    args.encode_uint32(0);

    XdrDecoder dec(args.data().data(), args.size());
    XdrEncoder reply;
    auto call = make_call();
    auto handlers = nfs_->get_handlers();
    handlers.procedures[NFSPROC3_SETATTR](call, dec, reply);

    XdrDecoder rdec(reply.data().data(), reply.size());
    uint32_t status = rdec.decode_uint32();
    EXPECT_EQ(status, static_cast<uint32_t>(NfsStat3::NFS3ERR_NOT_SYNC));
}

TEST_F(NfsProcTest, CreateGuardedDuplicate) {
    // Create a file first
    FileHandle file_fh;
    Fattr3 attr;
    fs_->create(root_fh_, "guarded.txt", 0644, file_fh, attr);

    // Try GUARDED create on same name — should fail with EXIST
    XdrEncoder args;
    encode_fh(args, root_fh_);
    args.encode_string("guarded.txt");
    args.encode_uint32(GUARDED); // createmode = GUARDED
    // sattr3
    args.encode_bool(true); args.encode_uint32(0644); // mode
    args.encode_bool(false); // uid
    args.encode_bool(false); // gid
    args.encode_bool(false); // size
    args.encode_uint32(0);   // atime
    args.encode_uint32(0);   // mtime

    XdrDecoder dec(args.data().data(), args.size());
    XdrEncoder reply;
    auto call = make_call();
    auto handlers = nfs_->get_handlers();
    handlers.procedures[NFSPROC3_CREATE](call, dec, reply);

    XdrDecoder rdec(reply.data().data(), reply.size());
    uint32_t status = rdec.decode_uint32();
    EXPECT_EQ(status, static_cast<uint32_t>(NfsStat3::NFS3ERR_EXIST));
}

TEST_F(NfsProcTest, DecodeSattr3Helper) {
    // Test the decode_sattr3 helper directly
    XdrEncoder enc;
    enc.encode_bool(true); enc.encode_uint32(0755);  // mode
    enc.encode_bool(true); enc.encode_uint32(1000);  // uid
    enc.encode_bool(false);                           // gid: don't set
    enc.encode_bool(true); enc.encode_uint64(4096);  // size
    enc.encode_uint32(1);                             // atime: SET_TO_SERVER_TIME
    enc.encode_uint32(2);                             // mtime: SET_TO_CLIENT_TIME
    enc.encode_uint32(1234); enc.encode_uint32(5678); // mtime value

    XdrDecoder dec(enc.data().data(), enc.size());
    auto sa = NfsServer::decode_sattr3(dec);

    EXPECT_EQ(sa.mode, 0755u);
    EXPECT_EQ(sa.uid, 1000u);
    EXPECT_EQ(sa.gid, UINT32_MAX); // not set
    EXPECT_EQ(sa.size, 4096u);
    EXPECT_EQ(sa.atime.how, NfsTimeSet::How::SET_TO_SERVER_TIME);
    EXPECT_EQ(sa.mtime.how, NfsTimeSet::How::SET_TO_CLIENT_TIME);
    EXPECT_EQ(sa.mtime.time.seconds, 1234u);
    EXPECT_EQ(sa.mtime.time.nseconds, 5678u);
}
