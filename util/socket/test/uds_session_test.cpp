/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
constexpr int32_t UID_ROOT { 0 };
} // namespace

class UDSSessionTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static constexpr char PROGRAM_NAME[] = "uds_sesion_test";
    const int32_t moduleType_ = 3;
    static inline int32_t pid_ = 0;
    int32_t writeFd_ = -1;
    int32_t readFd_ = -1;
    void SetUp() override;
    void TearDown() override;
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
 * @tc.name: Construct
 * @tc.desc: Verify uds session function EventsIsEmpty
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
 * @tc.name: SendMsg_type1_001
 * @tc.desc: Verify uds session function sendMsg
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
 * @tc.name: SendMsg_type1_002
 * @tc.desc: Verify uds session function SendMsg
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
 * @tc.name: SendMsg_type1_003
 * @tc.desc: Verify uds session function SendMsg
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
 * @tc.name: SendMsg_type1_004
 * @tc.desc: Verify uds session function SendMsg
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
 * @tc.name: SendMsg_type1_005
 * @tc.desc: Verify uds session function SendMsg
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
 * @tc.name: SendMsg_type2_001
 * @tc.desc: Verify uds session function SendMsg
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
 * @tc.name: SendMsg_type2_002
 * @tc.desc: Verify uds session function SendMsg
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
 * @tc.name: SendMsg_type2_003
 * @tc.desc: Verify uds session function SendMsg
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

/**
 * @tc.name: GetTimerIds
 * @tc.desc: Verify uds session function GetTimerIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, GetTimerIds, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);

    auto currentTime = GetSysClockTime();
    int32_t type = ANR_DISPATCH;
    int32_t timerId = 1;
    sesObj.SaveANREvent(type, 1, currentTime, timerId);

    std::vector<int32_t> ids = sesObj.GetTimerIds(type);
    if (ids.empty()) {
        ASSERT_FALSE(true);
    }
    EXPECT_EQ(ids[0], timerId);
}

/**
 * @tc.name: DelEvents
 * @tc.desc: Verify uds session function DelEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, DelEvents, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);

    int32_t type = ANR_DISPATCH;
    int32_t timerId = 0;
    const int32_t idLen = 5;
    int32_t i = 0;
    for (; i < idLen; ++i) {
        auto currentTime = GetSysClockTime();
        sesObj.SaveANREvent(type, i, currentTime, timerId + i);
    }

    std::list<int32_t> timerIds = sesObj.DelEvents(type, i - 2);
    EXPECT_EQ(timerIds.size(), idLen - 1);
}

/**
 * @tc.name: UDSSessionTest_DelEvents_01
 * @tc.desc: Verify uds session function DelEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_DelEvents_01, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    int32_t type = 3;
    int32_t id = 2;
    UDSSession::EventTime event;
    event.id = 4;
    event.eventTime = 1000;
    event.timerId = 5;

    int32_t key = 1;
    sesObj.events_[key].push_back(event);
    ASSERT_NO_FATAL_FAILURE(sesObj.DelEvents(type, id));
}

/**
 * @tc.name: UDSSessionTest_DelEvents_02
 * @tc.desc: Verify uds session function DelEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_DelEvents_02, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    int32_t type = 1;
    int32_t id = 2;
    UDSSession::EventTime event;
    event.id = 4;
    event.eventTime = 1000;
    event.timerId = 5;

    int32_t key = 1;
    sesObj.events_[key].push_back(event);
    ASSERT_NO_FATAL_FAILURE(sesObj.DelEvents(type, id));

    id = 5;
    ASSERT_NO_FATAL_FAILURE(sesObj.DelEvents(type, id));
}

/**
 * @tc.name: UDSSessionTest_GetEarliestEventTime_01
 * @tc.desc: Verify uds session function DelEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_GetEarliestEventTime_01, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    int32_t type = 1;
    UDSSession::EventTime event;
    event.id = 4;
    event.eventTime = 1000;
    event.timerId = 5;

    int32_t key = 1;
    sesObj.events_[key].push_back(event);
    int64_t ret = sesObj.GetEarliestEventTime(type);
    EXPECT_EQ(ret, 1000);

    type = 2;
    int64_t ret2 = sesObj.GetEarliestEventTime(type);
    EXPECT_EQ(ret2, 0);
}

/**
 * @tc.name: UDSSessionTest_SaveANREvent_01
 * @tc.desc: Verify uds session function SaveANREvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_SaveANREvent_01, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    int32_t type = 1;
    int32_t id = 2;
    int64_t time = 5;
    int32_t timerId = 6;
    UDSSession::EventTime event;
    event.id = 4;
    event.eventTime = 1000;
    event.timerId = 5;

    int32_t key = 1;
    sesObj.events_[key].push_back(event);
    ASSERT_NO_FATAL_FAILURE(sesObj.SaveANREvent(type, id, time, timerId));

    type = 3;
    ASSERT_NO_FATAL_FAILURE(sesObj.SaveANREvent(type, id, time, timerId));
}

/**
 * @tc.name: UDSSessionTest_GetTimerIds_01
 * @tc.desc: Verify uds session function GetTimerIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_GetTimerIds_01, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    int32_t type = 1;
    UDSSession::EventTime event;
    event.id = 4;
    event.eventTime = 1000;
    event.timerId = 5;

    int32_t key = 1;
    sesObj.events_[key].push_back(event);
    ASSERT_NO_FATAL_FAILURE(sesObj.GetTimerIds(type));

    type = 2;
    ASSERT_NO_FATAL_FAILURE(sesObj.GetTimerIds(type));
}

/**
 * @tc.name: UDSSessionTest_sendMsg_01
 * @tc.desc: Verify uds session function sendMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_sendMsg_01, TestSize.Level1)
{
    const char *buf = "123";
    size_t size = 0;
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    bool retResult = sesObj.SendMsg(buf, size);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name: UDSSessionTest_Close_01
 * @tc.desc: Verify uds session function Close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_Close_01, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    sesObj.fd_ = -1;
    ASSERT_NO_FATAL_FAILURE(sesObj.Close());
}

/**
 * @tc.name: UDSSessionTest_ReportSocketBufferFull_01
 * @tc.desc: Verify uds session function ReportSocketBufferFull
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, UDSSessionTest_ReportSocketBufferFull_01, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    ASSERT_NO_FATAL_FAILURE(sesObj.ReportSocketBufferFull());
}

/**
 * @tc.name: GetEarliestEventTime
 * @tc.desc: Verify uds session function GetEarliestEventTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, GetEarliestEventTime, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);

    int32_t type = ANR_DISPATCH;
    int32_t timerId = 0;
    const int32_t idLen = 5;
    int64_t currentTime = GetSysClockTime();
    int64_t earliestEventTime = currentTime;
    sesObj.SaveANREvent(type, 0, currentTime, timerId);
    for (int32_t i = 1; i < idLen; ++i) {
        currentTime = GetSysClockTime();
        sesObj.SaveANREvent(type, i, currentTime, timerId + i);
    }

    int64_t eventTime = sesObj.GetEarliestEventTime(type);
    EXPECT_EQ(eventTime, earliestEventTime);
}

/**
 * @tc.name: ReportSocketBufferFull
 * @tc.desc: Verify uds session function ReportSocketBufferFull
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UDSSessionTest, ReportSocketBufferFull, TestSize.Level1)
{
    UDSSession sesObj(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    ASSERT_NO_FATAL_FAILURE(sesObj.ReportSocketBufferFull());
    sesObj.lastReportTime_ = GetSysClockTime();
    sesObj.lastReportedPid_ = sesObj.pid_;
    ASSERT_NO_FATAL_FAILURE(sesObj.ReportSocketBufferFull());
}
} // namespace MMI
} // namespace OHOS
