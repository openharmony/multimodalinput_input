/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <sys/socket.h>

#include "proto.h"
#include "uds_session.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT = 0;
} // namespace

class UDSSessionTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static constexpr char PROGRAM_NAME[] = "uds_sesion_test";
    const int32_t moduleType_ = 3; // 3 CONNECT_MODULE_TYPE_ST_TEST
    static inline int32_t pid_ = 0;
    int32_t writeFd_ = -1;
    int32_t readFd_ = -1;
    void SetUp() override;
    void TearDown()  override;
};
void UDSSessionTest::SetUp()
{
    UDSSessionTest::pid_ = getpid();
    int32_t sockFds[2] = {};
    auto ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds);
    ASSERT_EQ(ret, 0);

    writeFd_ = sockFds[0];
    readFd_ = sockFds[1];
}

void UDSSessionTest::TearDown()
{
    close(writeFd_);
    writeFd_ = -1;
    close(readFd_);
    readFd_ = -1;
}

/**
 * @tc.name:Construct
 * @tc.desc:Verify uds session function EventsIsEmpty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, Construct, TestSize.Level1)
{
    UDSSession udsSession(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = udsSession.IsEventQueueEmpty();
    EXPECT_TRUE(retResult);
}

/**
 * @tc.name:SendMsg_type1_001
 * @tc.desc:Verify uds session function sendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type1_001, TestSize.Level1)
{
    const char *buf = "1234";
    size_t size = 4;
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(buf, size);
    EXPECT_TRUE(retResult);
}

/**
 * @tc.name:SendMsg_type1_002
 * @tc.desc:Verify uds session function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type1_002, TestSize.Level1)
{
    const char *buf = nullptr;
    size_t size = 4;

    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(buf, size);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name:SendMsg_type1_003
 * @tc.desc:Verify uds session function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type1_003, TestSize.Level1)
{
    const char *buf = nullptr;
    size_t size = 0;
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(buf, size);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name:SendMsg_type1_004
 * @tc.desc:Verify uds session function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type1_004, TestSize.Level1)
{
    const char *buf = "this unit data";
    size_t size = 14;

    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(buf, size);
    EXPECT_TRUE(retResult);
}

/**
 * @tc.name:SendMsg_type1_005
 * @tc.desc:Verify uds session function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type1_005, TestSize.Level1)
{
    const char *buf = "this unit data";
    size_t size = -1001;

    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(buf, size);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name:SendMsg_type2_001
 * @tc.desc:Verify uds session function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type2_001, TestSize.Level1)
{
    int32_t fd = -1;
    NetPacket pkt(MmiMessageId::INVALID);

    UDSSession sesObj(PROGRAM_NAME, moduleType_, fd, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(pkt);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name:SendMsg_type2_002
 * @tc.desc:Verify uds session function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type2_002, TestSize.Level1)
{
    NetPacket pkt(MmiMessageId::INVALID);

    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(pkt);
    EXPECT_TRUE(retResult);
}

/**
 * @tc.name:SendMsg_type2_003
 * @tc.desc:Verify uds session function SendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, SendMsg_type2_003, TestSize.Level1)
{
    int32_t fd = -65535;
    NetPacket pkt(MmiMessageId::INVALID);

    UDSSession sesObj(PROGRAM_NAME, moduleType_, fd, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(pkt);
    EXPECT_FALSE(retResult);
}
} // namespace MMI
} // namespace OHOS
