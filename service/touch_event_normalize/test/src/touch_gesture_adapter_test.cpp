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

#include <cstdio>
#include <gtest/gtest.h>

#include "input_event_handler.h"
#include "touch_gesture_adapter.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureAdapterTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class TouchGestureAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: TouchGestureAdapterTest_SetGestureEnable_001
 * @tc.desc: Test the funcation SetGestureEnable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_SetGestureEnable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = TOUCH_GESTURE_TYPE_SWIPE;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    touchGestureAdapter->Init();
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(false, adapterType, 0));
}

/**
 * @tc.name: TouchGestureAdapterTest_process_001
 * @tc.desc: Test the funcation process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_process_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    touchGestureAdapter->shouldDeliverToNext_ = true;
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
    touchGestureAdapter->shouldDeliverToNext_ = true;
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
    touchGestureAdapter->shouldDeliverToNext_ = false;
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
    touchGestureAdapter->shouldDeliverToNext_ = false;
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_Init_001
 * @tc.desc: Test the funcation Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_Init_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->Init());
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(adapterType, listener);
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->Init());
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->Init());
}

/**
 * @tc.name: TouchGestureAdapterTest_GetGestureFactory_001
 * @tc.desc: Test the funcation GetGestureFactory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetGestureFactory_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->GetGestureFactory());
}

/**
 * @tc.name: TouchGestureAdapterTest_OnTouchEvent_001
 * @tc.desc: Test the funcation OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnTouchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(adapterType, listener);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = false;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = false;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = true;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = true;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureType_ = 2;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnTouchEvent_002
 * @tc.desc: Test the funcation OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnTouchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(adapterType, listener);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    touchGestureAdapter->gestureStarted_ = true;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->gestureType_ = 2;
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    touchGestureAdapter->gestureStarted_ = true;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = false;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnSwipeGesture_001
 * @tc.desc: Test the funcation OnSwipeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnSwipeGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(adapterType, listener);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnSwipeGesture(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnSwipeGesture(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnPinchGesture_001
 * @tc.desc: Test the funcation OnPinchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnPinchGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(adapterType, listener);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnPinchGesture(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnPinchGesture(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnGestureEvent_001
 * @tc.desc: Test the funcation OnGestureEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnGestureEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    InputHandler->eventMonitorHandler_ = std::make_shared<EventMonitorHandler>();
    GestureMode mode = GestureMode::ACTION_SWIPE_DOWN;
    bool ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_SWIPE_UP;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_SWIPE_LEFT;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_SWIPE_RIGHT;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_PINCH_CLOSED;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_PINCH_OPENED;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_UNKNOWN;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TouchGestureAdapterTest_SetGestureEnable_002
 * @tc.desc: Test the funcation SetGestureEnable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_SetGestureEnable_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = TOUCH_GESTURE_TYPE_ALL;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    adapterType = TOUCH_GESTURE_TYPE_SWIPE;
    touchGestureAdapter->gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    adapterType = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(adapterType, listener);
    adapterType = TOUCH_GESTURE_TYPE_ALL;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    adapterType = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnTouchEvent_003
 * @tc.desc: Test the funcation OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnTouchEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(adapterType, listener);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->gestureType_ = 2;
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    touchGestureAdapter->gestureStarted_ = true;
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
}
} // namespace MMI
} // namespace OHOS