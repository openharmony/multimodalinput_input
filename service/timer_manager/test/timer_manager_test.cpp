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
    CALL_TEST_DEBUG;
    int32_t repeatCount = 3;
    int32_t intervalMs = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, AddTimerCallback);
    EXPECT_EQ(timerld, 0);
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_002
 * @tc.desc: Test the function RemoveTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t repeatCount = 3;
    int32_t intervalMs = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, AddTimerCallback);
    ASSERT_EQ(TimerMgr->RemoveTimer(timerld), 0);
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_003
 * @tc.desc: Test the function ResetTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t repeatCount = 3;
    int32_t intervalMs = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, AddTimerCallback);
    int32_t result = TimerMgr->ResetTimer(timerld);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_004
 * @tc.desc: Test the function IsExist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    int32_t repeatCount = 3;
    int32_t intervalMs = 1000;
    int32_t timerld = TimerMgr->AddTimer(intervalMs, repeatCount, nullptr);
    EXPECT_EQ(timerld, -1);
}

/**
 * @tc.name: TimerManagerTest_ManagerTimer_006
 * @tc.desc: Test the function RemoveTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ManagerTimer_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t repeatCount = 3;
    int32_t intervalMs = 1000;
    int32_t timerld = TimerMgr->AddTimerInternal(intervalMs, repeatCount, AddTimerCallback, "test006");
    ASSERT_EQ(TimerMgr->RemoveTimer(timerld, "test006"), 0);
}

/**
 * @tc.name: TimerManagerTest_AddTimer_001
 * @tc.desc: Test adding a timer to the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t intervalMs = 0;
    int32_t repeatCount = 1;
    auto callback = []() {};
    auto ret = timermanager.AddTimer(intervalMs, repeatCount, callback);
    EXPECT_EQ(ret, 0);
    intervalMs = -1;
    repeatCount = 1;
    ret = timermanager.AddTimer(intervalMs, repeatCount, callback);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: TimerManagerTest_RemoveTimer_001
 * @tc.desc: Test removing a timer from the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_RemoveTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t timerId = 1;
    auto ret = timermanager.RemoveTimer(timerId);
    EXPECT_EQ(ret, -1);
    timerId = -1;
    ret = timermanager.RemoveTimer(timerId);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: TimerManagerTest_ResetTimer_001
 * @tc.desc: Test resetting a timer in the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t timerId = 1;
    auto ret = timermanager.ResetTimer(timerId);
    EXPECT_EQ(ret, -1);
    timerId = -1;
    ret = timermanager.ResetTimer(timerId);
    EXPECT_EQ(ret, -1);
    ASSERT_NO_FATAL_FAILURE(timermanager.ProcessTimers());
}

/**
 * @tc.name: TimerManagerTest_IsExist_001
 * @tc.desc: Test checking if a timer exists in the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_IsExist_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t timerId = 1;
    auto ret = timermanager.IsExist(timerId);
    EXPECT_FALSE(ret);
    timerId = -1;
    ret = timermanager.IsExist(timerId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TimerManagerTest_CalcNextDelay_001
 * @tc.desc: Test calculating the next delayed timer in the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_CalcNextDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    auto ret = timermanager.CalcNextDelay();
    EXPECT_EQ(ret, -1);;
}

/**
 * @tc.name: TimerManagerTest_TakeNextTimerId_001
 * @tc.desc: Test obtaining the ID of the next timer in the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_TakeNextTimerId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    auto ret = timermanager.TakeNextTimerId();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddTimerInternal_001
 * @tc.desc: Test adding a timer internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerInternal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t intervalMs = 50;
    int32_t repeatCount = 1;
    auto callback = []() {};
    auto ret = timermanager.AddTimerInternal(intervalMs, repeatCount, callback);
    EXPECT_EQ(ret, 0);
    intervalMs = 11000;
    repeatCount = 1;
    ret = timermanager.AddTimerInternal(intervalMs, repeatCount, callback);
    EXPECT_EQ(ret, 1);
    intervalMs = 500;
    repeatCount = 1;
    ret = timermanager.AddTimerInternal(intervalMs, repeatCount, callback);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: TimerManagerTest_RemoveTimerInternal_001
 * @tc.desc: Test removing a timer internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_RemoveTimerInternal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t timerId = 1;
    auto ret = timermanager.RemoveTimerInternal(timerId);
    EXPECT_EQ(ret, -1);
    timerId = -1;
    ret = timermanager.RemoveTimerInternal(timerId);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: TimerManagerTest_ResetTimerInternal_001
 * @tc.desc: Test resetting a timer internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimerInternal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t timerId = 1;
    timermanager.AddTimer(timerId, 1000, []() {});
    auto ret = timermanager.ResetTimerInternal(timerId);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: TimerManagerTest_IsExistInternal_001
 * @tc.desc: Test checking if a timer exists internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_IsExistInternal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t timerId = 1;
    auto ret = timermanager.IsExistInternal(timerId);
    EXPECT_FALSE(ret);
    timerId = 2;
    ret = timermanager.IsExistInternal(timerId);
    EXPECT_FALSE(ret);
    timerId = -1;
    ret = timermanager.IsExistInternal(timerId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TimerManagerTest_InsertTimerInternal_001
 * @tc.desc: Test inserting a timer internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_InsertTimerInternal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    auto timer = std::make_unique<TimerManager::TimerItem>();
    timer->nextCallTime = 100;
    timermanager.InsertTimerInternal(timer);
    EXPECT_EQ(timermanager.timers_.front()->nextCallTime, 100);
}

/**
 * @tc.name: TimerManagerTest_InsertTimerInternal_002
 * @tc.desc: Test inserting a timer internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_InsertTimerInternal_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    auto timer1 = std::make_unique<TimerManager::TimerItem>();
    timer1->nextCallTime = 100;
    timermanager.InsertTimerInternal(timer1);
    auto timer2 = std::make_unique<TimerManager::TimerItem>();
    timer2->nextCallTime = 50;
    timermanager.InsertTimerInternal(timer2);
    EXPECT_EQ(timermanager.timers_.front()->nextCallTime, 50);
}

/**
 * @tc.name: TimerManagerTest_InsertTimerInternal_003
 * @tc.desc: Test inserting a timer internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_InsertTimerInternal_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    auto timer1 = std::make_unique<TimerManager::TimerItem>();
    timer1->nextCallTime = 100;
    timermanager.InsertTimerInternal(timer1);
    auto timer2 = std::make_unique<TimerManager::TimerItem>();
    timer2->nextCallTime = 200;
    timermanager.InsertTimerInternal(timer2);
    auto timer3 = std::make_unique<TimerManager::TimerItem>();
    timer3->nextCallTime = 200;
    timermanager.InsertTimerInternal(timer3);
    EXPECT_EQ(timermanager.timers_.front()->nextCallTime, 100);
}

/**
 * @tc.name: TimerManagerTest_CalcNextDelayInternal_001
 * @tc.desc: Test calculating the next delay internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_CalcNextDelayInternal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    int32_t timerId = 1;
    timermanager.AddTimer(timerId, 1000, []() {});
    int64_t millisTime = 36;
    EXPECT_EQ(timermanager.CalcNextDelayInternal(), millisTime);
}

/**
 * @tc.name: TimerManagerTest_CalcNextDelayInternal
 * @tc.desc: Test calculating the next delay internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_CalcNextDelayInternal, TestSize.Level1)
{
    TimerManager tMgr;
    auto timer = std::make_unique<TimerManager::TimerItem>();
    timer->nextCallTime = -1;
    tMgr.InsertTimerInternal(timer);
    EXPECT_EQ(tMgr.CalcNextDelayInternal(), 0);
}

/**
 * @tc.name: TimerManagerTest_ProcessTimersInternal_001
 * @tc.desc: Test processing timers internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ProcessTimersInternal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timermanager;
    ASSERT_NO_FATAL_FAILURE(timermanager.ProcessTimersInternal());
}

/**
 * @tc.name: TimerManagerTest_ProcessTimersInternal
 * @tc.desc: Test processing timers internally within the TimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ProcessTimersInternal, TestSize.Level1)
{
    TimerManager tMgr;
    auto timer = std::make_unique<TimerManager::TimerItem>();
    timer->nextCallTime = 10000000000;
    tMgr.InsertTimerInternal(timer);
    ASSERT_NO_FATAL_FAILURE(tMgr.ProcessTimersInternal());
}
} // namespace MMI
} // namespace OHOS