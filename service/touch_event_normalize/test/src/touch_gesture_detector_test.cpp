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

#include "touch_gesture_detector.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureDetectorTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class TouchGestureDetectorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class MyGestureListener : public TouchGestureDetector::GestureListener {
public:
    bool OnGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode) override
    {
        return true;
    }

    void OnGestureTrend(std::shared_ptr<PointerEvent> event) override {}
};

void TouchGestureDetectorTest::SetUpTestCase(void)
{}

void TouchGestureDetectorTest::TearDownTestCase(void)
{}

void TouchGestureDetectorTest::SetUp()
{}

void TouchGestureDetectorTest::TearDown()
{}

/**
 * @tc.name: TouchGestureDetectorTest_OnTouchEvent_01
 * @tc.desc: Test OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_OnTouchEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    detector.gestureEnable_ = true;
    detector.gestureDisplayId_ = INT32_MAX;
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    pointerEvent->SetPointerId(0);
    EXPECT_FALSE(detector.WhetherDiscardTouchEvent(pointerEvent));

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_OnTouchEvent_02
 * @tc.desc: Test OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_OnTouchEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    detector.gestureEnable_ = false;
    EXPECT_TRUE(detector.WhetherDiscardTouchEvent(pointerEvent));
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleDownEvent_01
 * @tc.desc: Test HandleDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleDownEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->pointerId_ = 3;
    detector.isRecognized_ = false;
    
    std::list<PointerEvent::PointerItem> pointers_;
    PointerEvent::PointerItem item1;
    item1.SetPointerId(1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(2);
    pointers_.push_back(item1);
    pointers_.push_back(item2);

    bool ret = pointerEvent->GetPointerItem(pointerEvent->pointerId_, item2);
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(detector.HandleDownEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleDownEvent_02
 * @tc.desc: Test HandleDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleDownEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    detector.isRecognized_ = true;
    ASSERT_NO_FATAL_FAILURE(detector.HandleDownEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleMoveEvent_01
 * @tc.desc: Test HandleMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleMoveEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.downPoint_[3] = Point(5.0f, 6.0f);

    detector.fingers_.insert(1);
    detector.fingers_.insert(0);
    detector.fingers_.insert(3);
    EXPECT_TRUE(detector.IsMatchGesture(ALL_FINGER_COUNT));

    detector.isRecognized_ = false;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));
    detector.gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));

    detector.gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));

    detector.gestureType_ = 8;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleMoveEvent_02
 * @tc.desc: Test HandleMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleMoveEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.downPoint_[3] = Point(5.0f, 6.0f);

    detector.fingers_.insert(1);
    detector.fingers_.insert(0);
    detector.fingers_.insert(3);
    detector.isRecognized_ = true;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleMoveEvent_03
 * @tc.desc: Test HandleMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleMoveEvent_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleSwipeMoveEvent_01
 * @tc.desc: Test HandleSwipeMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleSwipeMoveEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f, 150000);
    detector.isFingerReady_ = false;
    ASSERT_NO_FATAL_FAILURE(detector.HandleSwipeMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleSwipeMoveEvent_02
 * @tc.desc: Test HandleSwipeMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleSwipeMoveEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f, 150000);
    detector.downPoint_[3] = Point(5.0f, 6.0f, 200000);
    detector.isFingerReady_ = true;

    auto state = detector.ClacFingerMoveDirection(pointerEvent);
    state = TouchGestureDetector::SlideState::DIRECTION_UNKNOW;
    ASSERT_NO_FATAL_FAILURE(detector.HandleSwipeMoveEvent(pointerEvent));

    state = TouchGestureDetector::SlideState::DIRECTION_DOWN;
    GestureMode mode = detector.ChangeToGestureMode(state);
    EXPECT_FALSE(detector.NotifyGestureEvent(pointerEvent, mode));
    ASSERT_NO_FATAL_FAILURE(detector.HandleSwipeMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandlePinchMoveEvent_01
 * @tc.desc: Test HandlePinchMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandlePinchMoveEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    EXPECT_TRUE(detector.lastDistance_.empty());
    ASSERT_NO_FATAL_FAILURE(detector.HandlePinchMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandlePinchMoveEvent_02
 * @tc.desc: Test HandlePinchMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandlePinchMoveEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.downPoint_[3] = Point(5.0f, 6.0f);
    detector.downPoint_[4] = Point(7.0f, 8.0f);

    detector.lastDistance_[1] = 1.0;
    detector.lastDistance_[2] = 2.0;
    detector.lastDistance_[3] = 3.0;
    EXPECT_FALSE(detector.lastDistance_.empty());
    ASSERT_NO_FATAL_FAILURE(detector.HandlePinchMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleUpEvent_01
 * @tc.desc: Test HandleUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleUpEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerId_ = 1;
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    ASSERT_NO_FATAL_FAILURE(detector.HandleUpEvent(pointerEvent));

    pointerEvent->pointerId_ = 3;
    ASSERT_NO_FATAL_FAILURE(detector.HandleUpEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleUpEvent_02
 * @tc.desc: Test HandleUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleUpEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerId_ = 1;
    EXPECT_TRUE(detector.downPoint_.empty());
    ASSERT_NO_FATAL_FAILURE(detector.HandleUpEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_WhetherDiscardTouchEvent_01
 * @tc.desc: Test WhetherDiscardTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_WhetherDiscardTouchEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_MOUSE;
    EXPECT_TRUE(detector.WhetherDiscardTouchEvent(pointerEvent));

    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    detector.gestureEnable_ = false;
    EXPECT_TRUE(detector.WhetherDiscardTouchEvent(pointerEvent));

    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    detector.gestureEnable_ = true;
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    pointerEvent->SetPointerId(0);
    EXPECT_TRUE(detector.WhetherDiscardTouchEvent(pointerEvent));

    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    detector.gestureEnable_ = true;
    detector.gestureDisplayId_ = INT32_MAX - 2;
    pointerEvent->bitwise_ = 0;
    pointerEvent->SetPointerId(7);
    pointerEvent->targetDisplayId_ = INT32_MAX - 1;
    EXPECT_FALSE(detector.WhetherDiscardTouchEvent(pointerEvent));

    detector.gestureDisplayId_ = INT32_MAX;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_FALSE(detector.WhetherDiscardTouchEvent(pointerEvent));

    detector.gestureDisplayId_ = INT32_MAX;
    pointerEvent->targetDisplayId_ = INT32_MAX;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_FALSE(detector.WhetherDiscardTouchEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleFingerDown_01
 * @tc.desc: Test HandleFingerDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleFingerDown_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    auto fingersCount = detector.downPoint_.size();
    EXPECT_TRUE(fingersCount < 3);
    EXPECT_FALSE(detector.HandleFingerDown());
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleFingerDown_02
 * @tc.desc: Test HandleFingerDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleFingerDown_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(0.0f, 0.0f);
    detector.downPoint_[2] = Point(1000.0f, 1000.0f);
    detector.downPoint_[3] = Point(-1000.0f, -1000.0f);
    detector.downPoint_[4] = Point(500.0f, -500.0f);
    detector.downPoint_[5] = Point(-500.0f, 500.0f);
    EXPECT_FALSE(detector.HandleFingerDown());
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleFingerDown_03
 * @tc.desc: Test HandleFingerDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleFingerDown_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(0.0f, 0.0f);
    detector.downPoint_[2] = Point(100.0f, 100.0f);
    detector.downPoint_[3] = Point(200.0f, 200.0f);
    detector.downPoint_[4] = Point(300.0f, 300.0f);
    detector.downPoint_[5] = Point(400.0f, 400.0f);
    EXPECT_TRUE(detector.HandleFingerDown());
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleFingerDown_04
 * @tc.desc: Test HandleFingerDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleFingerDown_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(0.0f, 0.0f, 50000);
    detector.downPoint_[2] = Point(100.0f, 100.0f, 150000);
    detector.downPoint_[3] = Point(200.0f, 200.0f, 250000);
    EXPECT_FALSE(detector.HandleFingerDown());
}

/**
 * @tc.name: TouchGestureDetectorTest_GetMaxFingerSpacing_01
 * @tc.desc: Test GetMaxFingerSpacing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_GetMaxFingerSpacing_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    ASSERT_NO_FATAL_FAILURE(detector.GetMaxFingerSpacing());
}

/**
 * @tc.name: TouchGestureDetectorTest_GetMaxFingerSpacing_02
 * @tc.desc: Test GetMaxFingerSpacing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_GetMaxFingerSpacing_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.downPoint_[3] = Point(5.0f, 6.0f);
    ASSERT_NO_FATAL_FAILURE(detector.GetMaxFingerSpacing());
}

/**
 * @tc.name: TouchGestureDetectorTest_GetMaxDownInterval_01
 * @tc.desc: Test GetMaxDownInterval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_GetMaxDownInterval_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    ASSERT_NO_FATAL_FAILURE(detector.GetMaxDownInterval());
}

/**
 * @tc.name: TouchGestureDetectorTest_GetMaxDownInterval_02
 * @tc.desc: Test GetMaxDownInterval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_GetMaxDownInterval_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.downPoint_[3] = Point(5.0f, 6.0f);
    ASSERT_NO_FATAL_FAILURE(detector.GetMaxDownInterval());
}

/**
 * @tc.name: TouchGestureDetectorTest_GetSlidingDirection_01
 * @tc.desc: Test GetSlidingDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_GetSlidingDirection_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    double angle;
    angle = 20;
    ASSERT_NO_FATAL_FAILURE(detector.GetSlidingDirection(angle));
    angle = 50;
    ASSERT_NO_FATAL_FAILURE(detector.GetSlidingDirection(angle));
    angle = -60;
    ASSERT_NO_FATAL_FAILURE(detector.GetSlidingDirection(angle));
    angle = 200;
    ASSERT_NO_FATAL_FAILURE(detector.GetSlidingDirection(angle));
}

/**
 * @tc.name: TouchGestureDetectorTest_ChangeToGestureMode_01
 * @tc.desc: Test ChangeToGestureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_ChangeToGestureMode_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    TouchGestureDetector::SlideState state;
    state = TouchGestureDetector::SlideState::DIRECTION_UP;
    EXPECT_EQ(detector.ChangeToGestureMode(state), GestureMode::ACTION_SWIPE_UP);

    state = TouchGestureDetector::SlideState::DIRECTION_DOWN;
    EXPECT_EQ(detector.ChangeToGestureMode(state), GestureMode::ACTION_SWIPE_DOWN);

    state = TouchGestureDetector::SlideState::DIRECTION_LEFT;
    EXPECT_EQ(detector.ChangeToGestureMode(state), GestureMode::ACTION_SWIPE_LEFT);

    state = TouchGestureDetector::SlideState::DIRECTION_RIGHT;
    EXPECT_EQ(detector.ChangeToGestureMode(state), GestureMode::ACTION_SWIPE_RIGHT);

    state = TouchGestureDetector::SlideState::DIRECTION_UNKNOW;
    EXPECT_EQ(detector.ChangeToGestureMode(state), GestureMode::ACTION_UNKNOWN);
}

/**
 * @tc.name: TouchGestureDetectorTest_ClacFingerMoveDirection_01
 * @tc.desc: Test ClacFingerMoveDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_ClacFingerMoveDirection_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(detector.ClacFingerMoveDirection(pointerEvent));

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    ASSERT_NO_FATAL_FAILURE(detector.ClacFingerMoveDirection(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_ClacFingerMoveDirection_02
 * @tc.desc: Test ClacFingerMoveDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_ClacFingerMoveDirection_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.downPoint_[3] = Point(5.0f, 6.0f);
    ASSERT_NO_FATAL_FAILURE(detector.ClacFingerMoveDirection(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcGravityCenter_01
 * @tc.desc: Test CalcGravityCenter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcGravityCenter_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);
    points[3] = Point(5.0f, 6.0f);
    points[4] = Point(7.0f, 8.0f);
    points[5] = Point(9.0f, 10.0f);
    points[6] = Point(11.0f, 12.0f);
    int32_t count = static_cast<int32_t>(points.size());
    EXPECT_TRUE(count > 5);
    ASSERT_NO_FATAL_FAILURE(detector.CalcGravityCenter(points));
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcGravityCenter_02
 * @tc.desc: Test CalcGravityCenter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcGravityCenter_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);
    points[3] = Point(5.0f, 6.0f);
    ASSERT_NO_FATAL_FAILURE(detector.CalcGravityCenter(points));
}

/**
 * @tc.name: TouchGestureDetectorTest_IsFingerMove
 * @tc.desc: Test IsFingerMove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_IsFingerMove, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureDetector detector(TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    ASSERT_NO_FATAL_FAILURE(detector.IsFingerMove(Point(1.0f, 2.0f), Point(3.0f, 4.0f)));
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcTwoPointsDistance
 * @tc.desc: Test CalcTwoPointsDistance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcTwoPointsDistance, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureDetector detector(TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    ASSERT_NO_FATAL_FAILURE(detector.CalcTwoPointsDistance(Point(1.0f, 2.0f), Point(3.0f, 4.0f)));
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcClusterCenter_01
 * @tc.desc: Test CalcClusterCenter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcClusterCenter_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureDetector detector(TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    std::map<int32_t, Point> points;
    ASSERT_NO_FATAL_FAILURE(detector.CalcClusterCenter(points));
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcClusterCenter_02
 * @tc.desc: Test CalcClusterCenter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcClusterCenter_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureDetector detector(TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);
    points[3] = Point(5.0f, 6.0f);
    ASSERT_NO_FATAL_FAILURE(detector.CalcClusterCenter(points));
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcAndStoreDistance_01
 * @tc.desc: Test CalcAndStoreDistance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcAndStoreDistance_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);

    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    ASSERT_NO_FATAL_FAILURE(detector.CalcAndStoreDistance());
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcAndStoreDistance_02
 * @tc.desc: Test CalcAndStoreDistance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcAndStoreDistance_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);

    detector.downPoint_[1] = Point(1.0f, 2.0f, 50000);
    detector.downPoint_[2] = Point(3.0f, 4.0f, 150000);
    detector.downPoint_[3] = Point(5.0f, 6.0f, 250000);
    detector.downPoint_[4] = Point(7.0f, 8.0f, 350000);
    ASSERT_NO_FATAL_FAILURE(detector.CalcAndStoreDistance());
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcAndStoreDistance_03
 * @tc.desc: Test CalcAndStoreDistance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcAndStoreDistance_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);

    detector.downPoint_[1] = Point(1.0f, 2.0f, 5000);
    detector.downPoint_[2] = Point(3.0f, 4.0f, 6000);
    detector.downPoint_[3] = Point(5.0f, 6.0f, 7000);
    detector.downPoint_[4] = Point(7.0f, 8.0f, 8000);

    detector.lastDistance_[1] = 10.5;
    detector.lastDistance_[2] = 20.5;
    detector.lastDistance_[3] = 30.5;
    ASSERT_NO_FATAL_FAILURE(detector.CalcAndStoreDistance());
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcMultiFingerMovement_01
 * @tc.desc: Test CalcMultiFingerMovement
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcMultiFingerMovement_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);
    points[3] = Point(5.0f, 6.0f);

    detector.downPoint_[1] = Point(1.0f, 2.0f, 50000);
    detector.downPoint_[2] = Point(3.0f, 4.0f, 150000);
    detector.downPoint_[3] = Point(5.0f, 6.0f, 250000);
    ASSERT_NO_FATAL_FAILURE(detector.CalcMultiFingerMovement(points));
}

/**
 * @tc.name: TouchGestureDetectorTest_CalcMultiFingerMovement_02
 * @tc.desc: Test CalcMultiFingerMovement
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_CalcMultiFingerMovement_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> points;
    points[1] = Point(1.0f, 2.0f);
    points[2] = Point(3.0f, 4.0f);
    points[3] = Point(5.0f, 6.0f);

    detector.downPoint_[4] = Point(1.0f, 2.0f, 5000);
    detector.downPoint_[5] = Point(3.0f, 4.0f, 6000);
    detector.downPoint_[6] = Point(5.0f, 6.0f, 7000);
    ASSERT_NO_FATAL_FAILURE(detector.CalcMultiFingerMovement(points));
}

/**
 * @tc.name: TouchGestureDetectorTest_JudgeOperationMode_01
 * @tc.desc: Test JudgeOperationMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_JudgeOperationMode_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> movePoints;
    movePoints[1] = Point(1.0f, 2.0f);
    movePoints[2] = Point(3.0f, 4.0f);
    movePoints[3] = Point(5.0f, 6.0f);

    detector.downPoint_[4] = Point(1.0f, 2.0f, 5000);
    detector.downPoint_[5] = Point(3.0f, 4.0f, 6000);
    detector.downPoint_[6] = Point(5.0f, 6.0f, 7000);

    ASSERT_NO_FATAL_FAILURE(detector.JudgeOperationMode(movePoints));
}

/**
 * @tc.name: TouchGestureDetectorTest_JudgeOperationMode_02
 * @tc.desc: Test JudgeOperationMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_JudgeOperationMode_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> movePoints;
    movePoints[1] = Point(1.0f, 2.0f);
    movePoints[2] = Point(3.0f, 4.0f);
    movePoints[3] = Point(5.0f, 6.0f);

    detector.downPoint_[4] = Point(1.0f, 2.0f, 5000);
    detector.downPoint_[5] = Point(3.0f, 4.0f, 6000);
    detector.downPoint_[6] = Point(5.0f, 6.0f, 7000);
    detector.downPoint_[7] = Point(7.0f, 8.0f, 8000);

    ASSERT_NO_FATAL_FAILURE(detector.JudgeOperationMode(movePoints));
}

/**
 * @tc.name: TouchGestureDetectorTest_JudgeOperationMode_03
 * @tc.desc: Test JudgeOperationMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_JudgeOperationMode_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> movePoints;
    movePoints[1] = Point(1.0f, 2.0f);
    movePoints[2] = Point(3.0f, 4.0f);
    movePoints[3] = Point(5.0f, 6.0f);

    detector.downPoint_[1] = Point(1.0f, 2.0f, 5000);
    detector.downPoint_[2] = Point(3.0f, 4.0f, 6000);
    detector.downPoint_[3] = Point(5.0f, 6.0f, 7000);
    detector.downPoint_[4] = Point(7.0f, 8.0f, 8000);

    detector.lastDistance_[4] = 1.0;
    detector.lastDistance_[5] = 2.0;
    detector.lastDistance_[6] = 3.0;
    ASSERT_NO_FATAL_FAILURE(detector.JudgeOperationMode(movePoints));
}

/**
 * @tc.name: TouchGestureDetectorTest_JudgeOperationMode_04
 * @tc.desc: Test JudgeOperationMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_JudgeOperationMode_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::map<int32_t, Point> movePoints;
    movePoints[1] = Point(1.0f, 2.0f);
    movePoints[2] = Point(3.0f, 4.0f);
    movePoints[3] = Point(5.0f, 6.0f);
    movePoints[4] = Point(7.0f, 8.0f);

    detector.downPoint_[1] = Point(1.0f, 2.0f, 5000);
    detector.downPoint_[2] = Point(3.0f, 4.0f, 6000);
    detector.downPoint_[3] = Point(5.0f, 6.0f, 7000);
    detector.downPoint_[4] = Point(7.0f, 8.0f, 8000);

    detector.lastDistance_[1] = 1.0;
    detector.lastDistance_[2] = 2.0;
    detector.lastDistance_[3] = 3.0;
    detector.lastDistance_[4] = 4.0;
    ASSERT_NO_FATAL_FAILURE(detector.JudgeOperationMode(movePoints));
}

/**
 * @tc.name: TouchGestureDetectorTest_AntiJitter_01
 * @tc.desc: Test AntiJitter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_AntiJitter_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    GestureMode mode;
    mode = GestureMode::ACTION_PINCH_CLOSED;
    detector.continuousCloseCount_ = 3;
    EXPECT_FALSE(detector.AntiJitter(pointerEvent, mode));
    detector.continuousCloseCount_ = 1;
    EXPECT_FALSE(detector.AntiJitter(pointerEvent, mode));

    mode = GestureMode::ACTION_PINCH_OPENED;
    detector.continuousOpenCount_ = 3;
    EXPECT_FALSE(detector.AntiJitter(pointerEvent, mode));
    detector.continuousOpenCount_ = 1;
    EXPECT_FALSE(detector.AntiJitter(pointerEvent, mode));

    mode = GestureMode::ACTION_UNKNOWN;
    EXPECT_FALSE(detector.AntiJitter(pointerEvent, mode));
}

/**
 * @tc.name: TouchGestureDetectorTest_AddGestureFingers_01
 * @tc.desc: Test AddGestureFingers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_AddGestureFingers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.fingers_.insert(1);
    detector.fingers_.insert(2);
    detector.fingers_.insert(3);
    int32_t fingers = 1;
    ASSERT_NO_FATAL_FAILURE(detector.AddGestureFingers(fingers));
    fingers = 4;
    ASSERT_NO_FATAL_FAILURE(detector.AddGestureFingers(fingers));

    detector.fingers_.clear();
    ASSERT_NO_FATAL_FAILURE(detector.AddGestureFingers(fingers));
}

/**
 * @tc.name: TouchGestureDetectorTest_RemoveGestureFingers_01
 * @tc.desc: Test RemoveGestureFingers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_RemoveGestureFingers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.fingers_.insert(1);
    detector.fingers_.insert(2);
    detector.fingers_.insert(3);
    int32_t fingers = 1;
    ASSERT_NO_FATAL_FAILURE(detector.RemoveGestureFingers(fingers));
    fingers = 4;
    ASSERT_NO_FATAL_FAILURE(detector.RemoveGestureFingers(fingers));

    detector.fingers_.clear();
    ASSERT_NO_FATAL_FAILURE(detector.RemoveGestureFingers(fingers));
}

/**
 * @tc.name: TouchGestureDetectorTest_IsMatchGesture_01
 * @tc.desc: Test IsMatchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_IsMatchGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.fingers_.insert(1);
    detector.fingers_.insert(2);
    detector.fingers_.insert(3);

    int32_t count = 1;
    GestureMode mode;
    mode = GestureMode::ACTION_SWIPE_DOWN;
    EXPECT_TRUE(detector.IsMatchGesture(mode, count));
    mode = GestureMode::ACTION_SWIPE_UP;
    EXPECT_TRUE(detector.IsMatchGesture(mode, count));
    mode = GestureMode::ACTION_SWIPE_LEFT;
    EXPECT_TRUE(detector.IsMatchGesture(mode, count));
    mode = GestureMode::ACTION_SWIPE_RIGHT;
    EXPECT_TRUE(detector.IsMatchGesture(mode, count));
    mode = GestureMode::ACTION_PINCH_OPENED;
    EXPECT_FALSE(detector.IsMatchGesture(mode, count));
    mode = GestureMode::ACTION_PINCH_CLOSED;
    EXPECT_FALSE(detector.IsMatchGesture(mode, count));
    mode = GestureMode::ACTION_UNKNOWN;
    EXPECT_FALSE(detector.IsMatchGesture(mode, count));
}

/**
 * @tc.name: TouchGestureDetectorTest_IsMatchGesture_02
 * @tc.desc: Test IsMatchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_IsMatchGesture_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    detector.fingers_.insert(1);
    detector.fingers_.insert(2);
    detector.fingers_.insert(3);

    int32_t count = 4;
    GestureMode mode;
    mode = GestureMode::ACTION_UNKNOWN;
    EXPECT_FALSE(detector.IsMatchGesture(mode, count));
}

/**
 * @tc.name: TouchGestureDetectorTest_NotifyGestureEvent_01
 * @tc.desc: Test NotifyGestureEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_NotifyGestureEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    GestureMode mode;
    mode = GestureMode::ACTION_UNKNOWN;
    EXPECT_FALSE(detector.NotifyGestureEvent(pointerEvent, mode));

    mode = GestureMode::ACTION_GESTURE_END;
    for (auto i = 0; i < 5; i++) {
        PointerEvent::PointerItem pointerItem;
        detector.fingers_.insert(i + 1);
        pointerEvent->pointers_.push_back(pointerItem);
    }
    EXPECT_FALSE(detector.NotifyGestureEvent(pointerEvent, mode));
}

/**
 * @tc.name: TouchGestureDetectorTest_OnTouchEvent_003
 * @tc.desc: Test OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_OnTouchEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    detector.gestureEnable_ = true;
    inputEvent->bitwise_ = 0x00000000;
    pointerEvent->SetPointerId(5);
    detector.gestureDisplayId_ = INT32_MAX;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    EXPECT_FALSE(detector.OnTouchEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleDownEvent_003
 * @tc.desc: Test HandleDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleDownEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    detector.isRecognized_ = false;
    PointerEvent::PointerItem item1;
    item1.SetPointerId(1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(2);
    pointerEvent->pointers_.push_back(item1);
    pointerEvent->pointers_.push_back(item2);
    pointerEvent->SetPointerId(2);
    ASSERT_NO_FATAL_FAILURE(detector.HandleDownEvent(pointerEvent));
    detector.gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    ASSERT_NO_FATAL_FAILURE(detector.HandleDownEvent(pointerEvent));
    detector.gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(detector.HandleDownEvent(pointerEvent));
    detector.gestureType_ = TOUCH_GESTURE_TYPE_NONE;
    ASSERT_NO_FATAL_FAILURE(detector.HandleDownEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleMoveEvent_004
 * @tc.desc: Test HandleMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleMoveEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    detector.isRecognized_ = true;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));
    detector.isRecognized_ = false;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_HandlePinchMoveEvent_003
 * @tc.desc: Test HandlePinchMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandlePinchMoveEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.downPoint_[3] = Point(5.0f, 6.0f);
    detector.downPoint_[4] = Point(7.0f, 8.0f);
    detector.lastDistance_[1] = 1.0;
    detector.lastDistance_[2] = 2.0;
    detector.lastDistance_[3] = 3.0;
    PointerEvent::PointerItem item1;
    item1.SetPointerId(1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(2);
    pointerEvent->pointers_.push_back(item1);
    pointerEvent->pointers_.push_back(item2);
    pointerEvent->SetPointerId(2);
    ASSERT_NO_FATAL_FAILURE(detector.HandlePinchMoveEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureDetectorTest_IsPhysicalPointer_001
 * @tc.desc: Test IsPhysicalPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_IsPhysicalPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->bitwise_ = 0x00000000;
    pointerEvent->SetPointerId(5);
    bool ret = detector.IsPhysicalPointer(pointerEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TouchGestureDetectorTest_HandleUpEvent_003
 * @tc.desc: Test HandleUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureDetectorTest, TouchGestureDetectorTest_HandleUpEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<MyGestureListener>();
    TouchGestureType type = TOUCH_GESTURE_TYPE_SWIPE;
    TouchGestureDetector detector(type, listener);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerId_ = 1;
    detector.downPoint_[1] = Point(1.0f, 2.0f);
    detector.downPoint_[2] = Point(3.0f, 4.0f);
    detector.isRecognized_ = true;
    detector.lastTouchEvent_ = pointerEvent;
    ASSERT_NO_FATAL_FAILURE(detector.HandleUpEvent(pointerEvent));
}
} // namespace MMI
} // namespace OHOS