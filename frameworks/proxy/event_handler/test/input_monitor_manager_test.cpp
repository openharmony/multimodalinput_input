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

#include "i_input_event_consumer.h"
#include "input_monitor_manager.h"
#include "input_handler_type.h"
#include "tablet_event_input_subscribe_manager.h"
#include "mmi_log.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputMonitorManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputMonitorManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void TearDown()
    {
        IMonitorMgr.monitorHandlers_.clear();
        IMonitorMgr.actionsMonitorHandlers_.clear();
    }
};

class MonitorTestEventConsumer : public IInputEventConsumer {
public:
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override {}
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override {}
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {}
};

/**
 * @tc.name: MarkConsumed_Test_001
 * @tc.desc: Test MarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, MarkConsumed_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t monitorId = 1;
    int32_t eventId = 2;
    ASSERT_NO_FATAL_FAILURE(IMonitorMgr.MarkConsumed(monitorId, eventId));
}

/**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_001
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(IMonitorMgr.CheckMonitorValid(TOUCH_GESTURE_TYPE_SWIPE, ALL_FINGER_COUNT));
}

/**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_002
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(IMonitorMgr.CheckMonitorValid(TOUCH_GESTURE_TYPE_SWIPE, INVALID_HANDLER_ID));
}

 /**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_003
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(IMonitorMgr.CheckMonitorValid(TOUCH_GESTURE_TYPE_PINCH, MAX_FINGERS_COUNT));
}

 /**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_004
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(IMonitorMgr.CheckMonitorValid(TOUCH_GESTURE_TYPE_SWIPE, ERROR_EXCEED_MAX_COUNT));
}

 /**
 * @tc.name: CheckMonitorValid_ShouldReturnTrue_005
 * @tc.desc: Test CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(InputMonitorManagerTest, CheckMonitorValid_ShouldReturnTrue_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(IMonitorMgr.CheckMonitorValid(TOUCH_GESTURE_TYPE_NONE, FOUR_FINGER_COUNT));
}

/**
 * @tc.name: InputMonitorManagerTest_AddMonitor_NullConsumer_001
 * @tc.desc: Test AddMonitor with null consumer returns INVALID_HANDLER_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, InputMonitorManagerTest_AddMonitor_NullConsumer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IInputEventConsumer> monitor = nullptr;
    EXPECT_EQ(IMonitorMgr.AddMonitor(monitor, HANDLE_EVENT_TYPE_KP), INVALID_HANDLER_ID);
    std::vector<int32_t> actionsType { 1 };
    EXPECT_EQ(IMonitorMgr.AddMonitor(monitor, actionsType), INVALID_HANDLER_ID);
}

/**
 * @tc.name: InputMonitorManagerTest_AddMonitor_Actions_001
 * @tc.desc: Test AddMonitor with empty actions type registers a local monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, InputMonitorManagerTest_AddMonitor_Actions_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto monitor = std::make_shared<MonitorTestEventConsumer>();
    std::vector<int32_t> actionsType;
    int32_t monitorId = IMonitorMgr.AddMonitor(monitor, actionsType);
    ASSERT_GE(monitorId, 0);
    EXPECT_TRUE(IMonitorMgr.HasHandler(monitorId));
    EXPECT_EQ(IMonitorMgr.RemoveMonitor(monitorId), RET_OK);
    EXPECT_FALSE(IMonitorMgr.HasHandler(monitorId));
}

/**
 * @tc.name: InputMonitorManagerTest_RemoveMonitor_001
 * @tc.desc: Test RemoveMonitor with non-existent monitor id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, InputMonitorManagerTest_RemoveMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(IMonitorMgr.RemoveMonitor(1), RET_ERR);
    EXPECT_EQ(IMonitorMgr.RemoveMonitor(INVALID_HANDLER_ID), RET_ERR);
}

/**
 * @tc.name: InputMonitorManagerTest_MarkConsumed_Test_002
 * @tc.desc: Test MarkConsumed with an existing local monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, MarkConsumed_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto monitor = std::make_shared<MonitorTestEventConsumer>();
    std::vector<int32_t> actionsType;
    int32_t monitorId = IMonitorMgr.AddMonitor(monitor, actionsType);
    ASSERT_GE(monitorId, 0);
    int32_t eventId = 2;
    EXPECT_NO_FATAL_FAILURE(IMonitorMgr.MarkConsumed(monitorId, eventId));
    EXPECT_EQ(IMonitorMgr.RemoveMonitor(monitorId), RET_OK);
}

#ifdef OHOS_BUILD_ENABLE_TOUCH_GESTURE
/**
 * @tc.name: InputMonitorManagerTest_AddGestureMonitor_NullConsumer_001
 * @tc.desc: Test AddGestureMonitor with null consumer returns INVALID_HANDLER_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, InputMonitorManagerTest_AddGestureMonitor_NullConsumer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    EXPECT_EQ(IMonitorMgr.AddGestureMonitor(consumer, TOUCH_GESTURE_TYPE_PINCH, FOUR_FINGER_COUNT),
        INVALID_HANDLER_ID);
}

/**
 * @tc.name: InputMonitorManagerTest_RemoveGestureMonitor_001
 * @tc.desc: Test RemoveGestureMonitor with non-existent monitor id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputMonitorManagerTest, InputMonitorManagerTest_RemoveGestureMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(IMonitorMgr.RemoveGestureMonitor(1), RET_ERR);
}
#endif // OHOS_BUILD_ENABLE_TOUCH_GESTURE

} // namespace MMI
} // namespace OHOS