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

#include <fstream>

#include <gtest/gtest.h>

#include "mmi_log.h"
#include "uds_server.h"
#include "timer_manager.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t errCode { -1 };
constexpr int32_t rationId { 0 };
constexpr int32_t rightId { 1 };
} // namespace

class TimerManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

void AddTimerCallback()
{
    return;
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_001
 * @tc.desc: Test the function AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_001, TestSize.Level1)
{
    int32_t repeatCount = 3;
    int32_t intervalMs  = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, AddTimerCallback);
    EXPECT_EQ(timerld, rightId);
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_002
 * @tc.desc: Test the function RemoveTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_002, TestSize.Level1)
{
    int32_t repeatCount = 3;
    int32_t intervalMs  = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, AddTimerCallback);
    ASSERT_EQ(TimerMgr->RemoveTimer(timerld), rationId);
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_003
 * @tc.desc: Test the function ResetTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_003, TestSize.Level1)
{
    int32_t repeatCount = 3;
    int32_t intervalMs = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, AddTimerCallback);
    int32_t result = TimerMgr->ResetTimer(timerld);
    EXPECT_EQ(result, rationId);
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_004
 * @tc.desc: Test the function IsExist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_004, TestSize.Level1)
{
    int32_t repeatCount = 3;
    int32_t intervalMs = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, AddTimerCallback);
    ASSERT_TRUE(TimerMgr->IsExist(timerld));
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_005
 * @tc.desc: Test the function AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_005, TestSize.Level1)
{
    int32_t repeatCount = 3;
    int32_t intervalMs  = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, nullptr);
    EXPECT_EQ(timerld, errCode);
}
} // namespace MMI
} // namespace OHOS