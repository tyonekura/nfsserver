#include <gtest/gtest.h>
#include "nlm/nlm_types.h"
#include "nlm/nlm_server.h"
#include "nsm/nsm_client.h"

TEST(NlmTypes, ProgramAndVersion) {
    EXPECT_EQ(NLM_PROGRAM, 100021u);
    EXPECT_EQ(NLM_V4, 4u);
}

TEST(NlmTypes, ProcedureNumbers) {
    EXPECT_EQ(NLMPROC4_NULL, 0u);
    EXPECT_EQ(NLMPROC4_TEST, 1u);
    EXPECT_EQ(NLMPROC4_LOCK, 2u);
    EXPECT_EQ(NLMPROC4_CANCEL, 3u);
    EXPECT_EQ(NLMPROC4_UNLOCK, 4u);
    EXPECT_EQ(NLMPROC4_FREE_ALL, 23u);
}

TEST(NlmTypes, StatusCodes) {
    EXPECT_EQ(static_cast<uint32_t>(NlmStat::LCK_GRANTED), 0u);
    EXPECT_EQ(static_cast<uint32_t>(NlmStat::LCK_DENIED), 1u);
    EXPECT_EQ(static_cast<uint32_t>(NlmStat::LCK_DENIED_NOLOCKS), 2u);
    EXPECT_EQ(static_cast<uint32_t>(NlmStat::LCK_BLOCKED), 3u);
    EXPECT_EQ(static_cast<uint32_t>(NlmStat::LCK_DENIED_GRACE_PERIOD), 4u);
    EXPECT_EQ(static_cast<uint32_t>(NlmStat::LCK_DEADLCK), 5u);
}

TEST(NlmTypes, NlmLockDefault) {
    NlmLock lock;
    EXPECT_TRUE(lock.caller_name.empty());
    EXPECT_EQ(lock.svid, 0u);
    EXPECT_EQ(lock.offset, 0u);
    EXPECT_EQ(lock.length, 0u);
}

TEST(NsmTypes, ProgramAndVersion) {
    EXPECT_EQ(SM_PROGRAM, 100024u);
    EXPECT_EQ(SM_VERSION, 1u);
}

TEST(NsmTypes, ProcedureNumbers) {
    EXPECT_EQ(SM_MON, 2u);
    EXPECT_EQ(SM_UNMON, 3u);
    EXPECT_EQ(SM_UNMON_ALL, 4u);
}
