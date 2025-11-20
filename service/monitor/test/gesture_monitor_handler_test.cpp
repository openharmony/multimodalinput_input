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

#include "gesture_monitor_handler.h"
#include "pointer_event.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GestureMonitorHandlerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class GestureMonitorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventMonitorHandlerTest_CheckMonitorValid_001
 * @tc.desc: Test the function CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_CheckMonitorValid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    TouchGestureType type = 2;
    int32_t fingers = 0;
    bool ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_TRUE(ret);
    fingers = 4;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_TRUE(ret);
    type = 1;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_TRUE(ret);
    fingers = 10;
    type = 0;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_FALSE(ret);
    type = 5;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_CheckMonitorValid_002
 * @tc.desc: Test the function CheckMonitorValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_CheckMonitorValid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    TouchGestureType type = TOUCH_GESTURE_TYPE_ALL;
    int32_t fingers = FOUR_FINGER_COUNT;
    bool ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_TRUE(ret);
    type = TOUCH_GESTURE_TYPE_PINCH;
    fingers = THREE_FINGER_COUNT;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_FALSE(ret);
    type = TOUCH_GESTURE_TYPE_SWIPE;
    fingers = 2;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_FALSE(ret);
    type = TOUCH_GESTURE_TYPE_ALL;
    fingers = MAX_FINGERS_COUNT;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_TRUE(ret);
    type = 0xFFFFFFFF;
    fingers = FOUR_FINGER_COUNT;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_FALSE(ret);
    type = TOUCH_GESTURE_TYPE_ALL;
    fingers = -1;
    ret = handler.CheckMonitorValid(type, fingers);
    ASSERT_FALSE(ret);
}


/**
 * @tc.name: EventMonitorHandlerTest_IsTouchGestureEvent_001
 * @tc.desc: Test the function IsTouchGestureEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_IsTouchGestureEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    int32_t pointerAction = PointerEvent::TOUCH_ACTION_SWIPE_DOWN;
    bool ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_TRUE(ret);
    pointerAction = PointerEvent::TOUCH_ACTION_SWIPE_UP;
    ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_TRUE(ret);
    pointerAction = PointerEvent::TOUCH_ACTION_SWIPE_RIGHT;
    ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_TRUE(ret);
    pointerAction = PointerEvent::TOUCH_ACTION_SWIPE_LEFT;
    ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_TRUE(ret);
    pointerAction = PointerEvent::TOUCH_ACTION_PINCH_OPENED;
    ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_TRUE(ret);
    pointerAction = PointerEvent::TOUCH_ACTION_PINCH_CLOSEED;
    ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_TRUE(ret);
    pointerAction = PointerEvent::TOUCH_ACTION_GESTURE_END;
    ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_TRUE(ret);
    pointerAction = 99;
    ret = handler.IsTouchGestureEvent(pointerAction);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsMatchGesture_002
 * @tc.desc: Test the function IsMatchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_IsMatchGesture_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    int32_t action = PointerEvent::TOUCH_ACTION_GESTURE_END;
    int32_t count = 0;
    bool ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
    action = PointerEvent::TOUCH_ACTION_SWIPE_DOWN;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = PointerEvent::TOUCH_ACTION_SWIPE_UP;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = PointerEvent::TOUCH_ACTION_SWIPE_RIGHT;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = PointerEvent::TOUCH_ACTION_SWIPE_LEFT;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = PointerEvent::TOUCH_ACTION_PINCH_OPENED;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = PointerEvent::TOUCH_ACTION_PINCH_CLOSEED;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = 90;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsMatchGesture_003
 * @tc.desc: Test the function IsMatchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_IsMatchGesture_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    int32_t action = PointerEvent::TOUCH_ACTION_SWIPE_DOWN;
    int32_t count = 1;
    handler.touchGestureInfo_.insert(std::make_pair(100, std::set<int32_t>{1, 2, 3}));
    bool ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = PointerEvent::TOUCH_ACTION_PINCH_OPENED;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsMatchGesture_004
 * @tc.desc: Test the function IsMatchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_IsMatchGesture_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    int32_t action = PointerEvent::TOUCH_ACTION_SWIPE_DOWN;
    int32_t count = 1;
    handler.gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_SWIPE, std::set<int32_t>{1, 2, 3}));
    bool ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
    handler.gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    handler.gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    auto range = handler.touchGestureInfo_.equal_range(TOUCH_GESTURE_TYPE_SWIPE);
    handler.touchGestureInfo_.erase(range.first, range.second);
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_SWIPE, std::set<int32_t>{2, 3}));
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    action = PointerEvent::TOUCH_ACTION_PINCH_OPENED;
    handler.gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_PINCH, std::set<int32_t>{1, 2, 3}));
    ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
    handler.gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
    handler.gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    range = handler.touchGestureInfo_.equal_range(TOUCH_GESTURE_TYPE_PINCH);
    handler.touchGestureInfo_.erase(range.first, range.second);
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_PINCH, std::set<int32_t>{2, 3}));
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsMatchGesture_005
 * @tc.desc: Test the function IsMatchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_IsMatchGesture_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    int32_t action = PointerEvent::TOUCH_ACTION_SWIPE_DOWN;
    int32_t count = 1;
    handler.gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_ALL, std::set<int32_t>{1, 2, 3}));
    bool ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
    action = PointerEvent::TOUCH_ACTION_PINCH_OPENED;
    handler.gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
    handler.gestureType_ = TOUCH_GESTURE_TYPE_ALL;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
    handler.gestureType_ = TOUCH_GESTURE_TYPE_NONE;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsMatchGesture_006
 * @tc.desc: Test the function IsMatchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_IsMatchGesture_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    int32_t action = PointerEvent::TOUCH_ACTION_SWIPE_DOWN;
    int32_t count = 1;
    handler.gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_SWIPE, std::set<int32_t>{ALL_FINGER_COUNT}));
    bool ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
    handler.gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_PINCH, std::set<int32_t>{ALL_FINGER_COUNT}));
    action = PointerEvent::TOUCH_ACTION_PINCH_OPENED;
    ret = handler.IsMatchGesture(action, count);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_AddGestureMonitor
 * @tc.desc: Test the function AddGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_AddGestureMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    TouchGestureType type = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = THREE_FINGER_COUNT;
    EXPECT_NO_FATAL_FAILURE(handler.AddGestureMonitor(type, fingers));
    type = TOUCH_GESTURE_TYPE_PINCH;
    handler.touchGestureInfo_.insert(std::make_pair(2, std::set<int32_t>{1, 2}));
    EXPECT_NO_FATAL_FAILURE(handler.AddGestureMonitor(type, fingers));
    type = TOUCH_GESTURE_TYPE_SWIPE;
    EXPECT_NO_FATAL_FAILURE(handler.AddGestureMonitor(type, fingers));
}

/**
 * @tc.name: EventMonitorHandlerTest_AddGestureMonitor_001
 * @tc.desc: Test the function AddGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_AddGestureMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    TouchGestureType type = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = THREE_FINGER_COUNT;
    EXPECT_NO_FATAL_FAILURE(handler.AddGestureMonitor(type, fingers));
    type = TOUCH_GESTURE_TYPE_PINCH;
    handler.touchGestureInfo_.insert(std::make_pair(2, std::set<int32_t>{1, 2}));
    EXPECT_NO_FATAL_FAILURE(handler.AddGestureMonitor(type, fingers));
    type = TOUCH_GESTURE_TYPE_SWIPE;
    EXPECT_NO_FATAL_FAILURE(handler.AddGestureMonitor(type, fingers));
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveGestureMonitor_001
 * @tc.desc: Test the function RemoveGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_RemoveGestureMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    TouchGestureType type = TOUCH_GESTURE_TYPE_PINCH;
    int32_t fingers = THREE_FINGER_COUNT;
    bool ret = handler.RemoveGestureMonitor(type, fingers);
    ASSERT_FALSE(ret);
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_PINCH, std::set<int32_t>{}));
    ret = handler.RemoveGestureMonitor(type, fingers);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveGestureMonitor_002
 * @tc.desc: Test the function RemoveGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GestureMonitorHandlerTest, EventMonitorHandlerTest_RemoveGestureMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    GestureMonitorHandler handler;
    TouchGestureType type = TOUCH_GESTURE_TYPE_PINCH;
    int32_t fingers = THREE_FINGER_COUNT;
    handler.touchGestureInfo_.insert(std::make_pair(type, std::set<int32_t>{ fingers, FOUR_FINGER_COUNT}));
    handler.touchGestureInfo_.insert(std::make_pair(TOUCH_GESTURE_TYPE_SWIPE, std::set<int32_t>{ FOUR_FINGER_COUNT}));
    bool ret = handler.RemoveGestureMonitor(TOUCH_GESTURE_TYPE_SWIPE, FOUR_FINGER_COUNT);
    ASSERT_FALSE(ret);
    ret = handler.RemoveGestureMonitor(type, FOUR_FINGER_COUNT);
    ASSERT_FALSE(ret);
    ret = handler.RemoveGestureMonitor(type, fingers);
    ASSERT_TRUE(ret);
}
} // namespace MMI
} // namespace MMI