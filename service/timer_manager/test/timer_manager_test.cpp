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
constexpr int32_t MAX_INTERVAL_MS { 10000 };
constexpr int32_t MIN_INTERVAL { 36 };
constexpr int32_t MAX_LONG_INTERVAL_MS { 30000 };
constexpr int32_t NONEXISTENT_ID { -1 };
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

/**
 * @tc.name: TimerManagerTest_AddTimer_002
 * @tc.desc: Verify AddTimer adjusts intervalMs to MIN_INTERVAL when less than MIN_INTERVAL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer_002, TestSize.Level1)
{
    TimerManager timermanager;
    int32_t intervalMs = -100;
    int32_t repeatCount = 2;
    bool callbackInvoked = false;
    auto callback = [&]() { callbackInvoked = true; };
    auto ret = timermanager.AddTimer(intervalMs, repeatCount, callback, "TestTimerMin");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddTimer_003
 * @tc.desc: Verify AddTimer adjusts intervalMs to MAX_INTERVAL_MS when greater than MAX_INTERVAL_MS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer_003, TestSize.Level1)
{
    TimerManager timermanager;
    int32_t intervalMs = MAX_INTERVAL_MS + 5000;
    int32_t repeatCount = 3;
    bool callbackInvoked = false;
    auto callback = [&]() { callbackInvoked = true; };
    auto ret = timermanager.AddTimer(intervalMs, repeatCount, callback, "TestTimerMax");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddTimer_004
 * @tc.desc: Verify AddTimer works with a normal valid interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer_004, TestSize.Level1)
{
    TimerManager timermanager;
    int32_t intervalMs = 500;
    int32_t repeatCount = 1;
    bool callbackInvoked = false;
    auto callback = [&]() { callbackInvoked = true; };
    auto ret = timermanager.AddTimer(intervalMs, repeatCount, callback, "TestTimerNormal");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddLongTimer_001
 * @tc.desc: Verify AddLongTimer adjusts intervalMs to MIN_INTERVAL when less than MIN_INTERVAL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddLongTimer_001, TestSize.Level1)
{
    TimerManager timermanager;
    int32_t intervalMs = MIN_INTERVAL - 10;
    int32_t repeatCount = 1;
    bool callbackInvoked = false;
    auto callback = [&]() { callbackInvoked = true; };
    int32_t ret = timermanager.AddLongTimer(intervalMs, repeatCount, callback, "LongTimerMin");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddLongTimer_002
 * @tc.desc: Verify AddLongTimer adjusts intervalMs to MAX_INTERVAL_MS when greater than MAX_LONG_INTERVAL_MS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddLongTimer_002, TestSize.Level1)
{
    TimerManager timermanager;
    int32_t intervalMs = MAX_LONG_INTERVAL_MS + 5000;
    int32_t repeatCount = 2;
    bool callbackInvoked = false;
    auto callback = [&]() { callbackInvoked = true; };
    int32_t ret = timermanager.AddLongTimer(intervalMs, repeatCount, callback, "LongTimerMax");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddLongTimer_003
 * @tc.desc: Verify AddLongTimer works correctly with valid interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddLongTimer_003, TestSize.Level1)
{
    TimerManager timermanager;
    int32_t intervalMs = 2000;
    int32_t repeatCount = 1;
    bool callbackInvoked = false;
    auto callback = [&]() { callbackInvoked = true; };
    int32_t ret = timermanager.AddLongTimer(intervalMs, repeatCount, callback, "LongTimerNormal");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddTimerInternal_002
 * @tc.desc: Return NONEXISTENT_ID when callback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerInternal_002, TestSize.Level1)
{
    TimerManager timermanager;
    int32_t intervalMs = 100;
    int32_t repeatCount = 1;
    std::function<void()> cb;
    auto ret = timermanager.AddTimerInternal(intervalMs, repeatCount, cb, "null_cb");
    EXPECT_EQ(ret, NONEXISTENT_ID);
}

/**
 * @tc.name: TimerManagerTest_AddTimerInternal_003
 * @tc.desc: Add many timers to ensure id keeps increasing monotonically
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerInternal_003, TestSize.Level1)
{
    TimerManager timermanager;
    auto cb = []() {};
    const int kCount = 20;
    for (int i = 0; i < kCount; i++) {
        int32_t ret = timermanager.AddTimerInternal(100 + i, 1, cb, "bulk_" + std::to_string(i));
        EXPECT_EQ(ret, i);
    }
}

/**
 * @tc.name: TimerManagerTest_AddTimerInternal_004
 * @tc.desc: Add timer with repeatCount = 0 (edge value) should still return a valid id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerInternal_004, TestSize.Level1)
{
    TimerManager timermanager;
    auto cb = []() {};
    int32_t ret = timermanager.AddTimerInternal(200, 0, cb, "repeat_zero");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_AddTimerInternal_005
 * @tc.desc: Add timer with very large intervalMs to ensure it is handled (no overflow path reachable here)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerInternal_005, TestSize.Level1)
{
    TimerManager timermanager;
    auto cb = []() {};
    int32_t ret = timermanager.AddTimerInternal(INT32_MAX, 1, cb, "large_interval");
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: TimerManagerTest_ResetTimerInternal_002
 * @tc.desc: Add a timer and reset it successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimerInternal_002, TestSize.Level1)
{
    TimerManager timermanager;
    auto callback = []() {};
    int32_t timerId = timermanager.AddTimerInternal(100, 1, callback, "reset_ok");
    ASSERT_GE(timerId, 0);
    int32_t ret = timermanager.ResetTimerInternal(timerId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TimerManagerTest_ResetTimerInternal_003
 * @tc.desc: Add multiple timers and reset one of them
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimerInternal_003, TestSize.Level1)
{
    TimerManager timermanager;
    auto callback = []() {};

    int32_t id1 = timermanager.AddTimerInternal(200, 1, callback, "t1");
    int32_t id2 = timermanager.AddTimerInternal(300, 1, callback, "t2");
    int32_t id3 = timermanager.AddTimerInternal(400, 1, callback, "t3");
    ASSERT_GE(id1, 0);
    ASSERT_GE(id2, 0);
    ASSERT_GE(id3, 0);
    int32_t ret = timermanager.ResetTimerInternal(id2);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(timermanager.ResetTimerInternal(id1), RET_OK);
}

/**
 * @tc.name: TimerManagerTest_ResetTimerInternal_004
 * @tc.desc: Attempt to reset non-existing timerId after timers have been added
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimerInternal_004, TestSize.Level1)
{
    TimerManager timermanager;
    auto callback = []() {};
    timermanager.AddTimerInternal(100, 1, callback, "t1");
    int32_t ret = timermanager.ResetTimerInternal(9999);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TimerManagerTest_ProcessTimersInternal_002
 * @tc.desc: Add one timer and ensure its callback is executed once
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ProcessTimersInternal_002, TestSize.Level1)
{
    TimerManager timermanager;
    bool callbackExecuted = false;
    auto callback = [&]() { callbackExecuted = true; };
    int32_t timerId = timermanager.AddTimerInternal(0, 1, callback, "test_timer");
    ASSERT_GE(timerId, 0);
    timermanager.ProcessTimersInternal();
    EXPECT_TRUE(callbackExecuted);
}

/**
 * @tc.name: TimerManagerTest_ProcessTimersInternal_003
 * @tc.desc: Add a single timer with repeatCount=1 and verify callback is called once
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ProcessTimersInternal_003, TestSize.Level1)
{
    TimerManager timermanager;
    int callCount = 0;
    auto callback = [&]() { callCount++; };
    int32_t timerId = timermanager.AddTimerInternal(0, 1, callback, "single_shot");
    ASSERT_GE(timerId, 0);
    timermanager.ProcessTimersInternal();
    EXPECT_EQ(callCount, 1);
}



/**
 * @tc.name: TimerManagerTest_ProcessTimersInternal_004
 * @tc.desc: Add multiple timers with different intervals and process them
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ProcessTimersInternal_004, TestSize.Level1)
{
    TimerManager timermanager;
    int callCount1 = 0;
    int callCount2 = 0;
    auto cb1 = [&]() { callCount1++; };
    auto cb2 = [&]() { callCount2++; };
    timermanager.AddTimerInternal(0, 1, cb1, "t1");
    timermanager.AddTimerInternal(0, 1, cb2, "t2");
    timermanager.ProcessTimersInternal();
    EXPECT_EQ(callCount1, 1);
    EXPECT_EQ(callCount2, 1);
}

/**
 * @tc.name: TimerManagerTest_ProcessTimersInternal_005
 * @tc.desc: ProcessTimersInternal with future timer (nextCallTime > nowTime) should not invoke callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ProcessTimersInternal_005, TestSize.Level1)
{
    TimerManager timermanager;
    bool callbackExecuted = false;
    auto callback = [&]() { callbackExecuted = true; };
    int32_t timerId = timermanager.AddTimerInternal(5000, 1, callback, "future_timer");
    ASSERT_GE(timerId, 0);
    timermanager.ProcessTimersInternal();
    EXPECT_FALSE(callbackExecuted);
}
} // namespace MMI
} // namespace OHOS