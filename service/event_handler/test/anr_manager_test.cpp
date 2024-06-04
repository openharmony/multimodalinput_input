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
} // namespace MMI
} // namespace OHOS