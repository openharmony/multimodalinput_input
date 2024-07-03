/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <libinput.h>

#include "anr_manager.h"
#include "dfx_hisysevent.h"
#include "input_event_handler.h"
#include "i_input_windows_manager.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "proto.h"
#include "timer_manager.h"
#include "window_manager.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string PROGRAM_NAME = "uds_session_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = 1;
constexpr int32_t UDS_UID = 100;
constexpr int32_t UDS_PID = 100;
} // namespace

class AnrManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: AnrManagerTest_MarkProcessed_001
 * @tc.desc: Features of the mark processed function
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_MarkProcessed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->Init(udsServer));
    int32_t pid = 123;
    int32_t eventType = 1;
    int32_t eventId = 456;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->MarkProcessed(pid, eventType, eventId));
}

/**
 * @tc.name: AnrManagerTest_RemoveTimers_001
 * @tc.desc: Features of the remove timers function
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_RemoveTimers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->Init(udsServer));
    SessionPtr sess;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->RemoveTimers(sess));
}

/**
 * @tc.name: AnrManagerTest_RemoveTimersByType_001
 * @tc.desc: Remove timers by type abnormal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_RemoveTimersByType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->Init(udsServer));
    SessionPtr session;
    int32_t dispatchType = -1;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->RemoveTimersByType(session, dispatchType));
}

/**
 * @tc.name: AnrManagerTest_RemoveTimersByType_002
 * @tc.desc: Remove timers by type abnormal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_RemoveTimersByType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->Init(udsServer));
    SessionPtr session;
    int32_t monitorType = 0;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->RemoveTimersByType(session, monitorType));
}

/**
 * @tc.name: AnrManagerTest_RemoveTimersByType_003
 * @tc.desc: Remove timers by type normal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_RemoveTimersByType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->Init(udsServer));
    SessionPtr session;
    int32_t illegalType = 123;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->RemoveTimersByType(session, illegalType));
}

/**
 * @tc.name: AnrManagerTest_SetANRNoticedPid_001
 * @tc.desc: Set noticed pid normal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_SetANRNoticedPid_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->Init(udsServer));
    int32_t pid = 1234;
    int32_t ret = ANRMgr->SetANRNoticedPid(pid);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AnrManagerTest_SetANRNoticedPid_002
 * @tc.desc: Set noticed pid abnormal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_SetANRNoticedPid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    ASSERT_NO_FATAL_FAILURE(ANRMgr->Init(udsServer));
    int32_t pid = -1;
    int32_t ret = ANRMgr->SetANRNoticedPid(pid);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AnrManagerTest_AddTimer_001
 * @tc.desc: Add timer function normal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_AddTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = 1;
    int32_t id = 1001;
    int64_t currentTime = 123456789;
    SessionPtr sess = std::shared_ptr<OHOS::MMI::UDSSession>();
    ASSERT_NO_FATAL_FAILURE(ANRMgr->AddTimer(type, id, currentTime, sess));
}

/**
 * @tc.name: AnrManagerTest_AddTimer_002
 * @tc.desc: Add timer function abnormal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_AddTimer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = -1;
    int32_t id = -2;
    int64_t currentTime = 123456789;
    SessionPtr sess = std::shared_ptr<OHOS::MMI::UDSSession>();
    ASSERT_NO_FATAL_FAILURE(ANRMgr->AddTimer(type, id, currentTime, sess));
}

/**
 * @tc.name: AnrManagerTest_TriggerANR_001
 * @tc.desc: Trigger function normal
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_TriggerANR_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = 1;
    int64_t time = 123456789;
    SessionPtr sess = std::shared_ptr<OHOS::MMI::UDSSession>();
    bool result = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: AnrManagerTest_MarkProcessed_002
 * @tc.desc: Cover the else branch of the if (pid_ != pid)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_MarkProcessed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ANRManager anrMgr;
    UDSServer udsServer;
    int32_t pid = 10;
    int32_t eventType = 1;
    int32_t eventId = 100;
    udsServer.pid_ = 20;
    anrMgr.pid_ = 10;
    anrMgr.udsServer_ = &udsServer;
    ASSERT_EQ(anrMgr.MarkProcessed(pid, eventType, eventId), RET_ERR);
}

/**
 * @tc.name: AnrManagerTest_AddTimer_003
 * @tc.desc: Cover the else branch of the
 * <br> if (sess->GetTokenType() != TokenType::TOKEN_HAP || sess->GetProgramName() == FOUNDATION)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_AddTimer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ANRManager anrMgr;
    int32_t type = ANR_MONITOR;
    int32_t id = 1;
    int64_t currentTime = 100;
    std::string programName = "foundation";
    SessionPtr sess = std::make_shared<UDSSession>(programName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    sess->SetTokenType(TokenType::TOKEN_NATIVE);
    ASSERT_NO_FATAL_FAILURE(anrMgr.AddTimer(type, id, currentTime, sess));

    sess->SetTokenType(TokenType::TOKEN_HAP);
    ASSERT_NO_FATAL_FAILURE(anrMgr.AddTimer(type, id, currentTime, sess));
}

/**
 * @tc.name: AnrManagerTest_AddTimer_004
 * @tc.desc:Cover the else branch of the if (anrTimerCount_ >= MAX_TIMER_COUNT)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_AddTimer_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ANRManager anrMgr;
    int32_t type = ANR_MONITOR;
    int32_t id = 1;
    int64_t currentTime = 100;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    sess->SetTokenType(TokenType::TOKEN_HAP);
    anrMgr.anrTimerCount_ = 51;
    ASSERT_NO_FATAL_FAILURE(anrMgr.AddTimer(type, id, currentTime, sess));

    anrMgr.anrTimerCount_ = 49;
    ASSERT_NO_FATAL_FAILURE(anrMgr.AddTimer(type, id, currentTime, sess));
}

/**
 * @tc.name: AnrManagerTest_RemoveTimers_002
 * @tc.desc: Cover the RemoveTimers function branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_RemoveTimers_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ANRManager anrMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::vector<UDSSession::EventTime> events { { 0, 0, -1 }, { 1, 1, 10 } };
    sess->events_[ANR_DISPATCH] = events;
    sess->events_[ANR_MONITOR] = events;
    ASSERT_NO_FATAL_FAILURE(anrMgr.RemoveTimers(sess));
}

/**
 * @tc.name: AnrManagerTest_RemoveTimersByType_004
 * @tc.desc: Cover the RemoveTimersByType function branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_RemoveTimersByType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ANRManager anrMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    int32_t type = 5;
    ASSERT_NO_FATAL_FAILURE(anrMgr.RemoveTimersByType(sess, type));

    type = ANR_DISPATCH;
    std::vector<UDSSession::EventTime> events { { 0, 0, -1 }, { 1, 1, 10 } };
    sess->events_[ANR_MONITOR] = events;
    ASSERT_NO_FATAL_FAILURE(anrMgr.RemoveTimersByType(sess, type));
}

/**
 * @tc.name: AnrManagerTest_TriggerANR_002
 * @tc.desc: Cover the TriggerANR function branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_TriggerANR_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ANRManager anrMgr;
    int32_t type = ANR_MONITOR;
    int64_t time = 1;
    std::string programName = "foundation";
    SessionPtr sess = std::make_shared<UDSSession>(programName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    UDSServer udsServer;
    anrMgr.udsServer_ = &udsServer;
    sess->SetTokenType(TokenType::TOKEN_NATIVE);
    EXPECT_FALSE(anrMgr.TriggerANR(type, time, sess));

    sess->SetTokenType(TokenType::TOKEN_HAP);
    EXPECT_FALSE(anrMgr.TriggerANR(type, time, sess));

    bool status = true;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    session->SetTokenType(TokenType::TOKEN_HAP);
    session->SetAnrStatus(type, status);
    EXPECT_TRUE(anrMgr.TriggerANR(type, time, session));

    type = ANR_DISPATCH;
    status = false;
    EXPECT_FALSE(anrMgr.TriggerANR(type, time, session));
}

/**
 * @tc.name: AnrManagerTest_OnSessionLost
 * @tc.desc: Cover the OnSessionLost function branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AnrManagerTest, AnrManagerTest_OnSessionLost, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ANRManager anrMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    anrMgr.anrNoticedPid_ = UDS_PID;
    ASSERT_NO_FATAL_FAILURE(anrMgr.OnSessionLost(sess));

    anrMgr.anrNoticedPid_ = 200;
    ASSERT_NO_FATAL_FAILURE(anrMgr.OnSessionLost(sess));
}
} // namespace MMI
} // namespace OHOS