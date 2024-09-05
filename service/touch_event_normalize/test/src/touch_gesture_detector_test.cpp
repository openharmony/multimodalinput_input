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

    detector.isRecognized_ = false;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));
    detector.gestureType_= TOUCH_GESTURE_TYPE_SWIPE;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));

    detector.gestureType_= TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(detector.HandleMoveEvent(pointerEvent));

    detector.gestureType_= 8;
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

    detector.isRecognized_ = true;
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
    detector.downPoint_[2] = Point(3.0f, 4.0f, 123456789);
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
    detector.downPoint_[2] = Point(3.0f, 4.0f, 123456789);
    detector.downPoint_[3] = Point(5.0f, 6.0f, 987654321);
    detector.isFingerReady_ = true;

    auto state = detector.ClacFingerMoveDirection(pointerEvent);
    state = TouchGestureDetector::SlideState::DIRECTION_UNKNOW;
    ASSERT_NO_FATAL_FAILURE(detector.HandleSwipeMoveEvent(pointerEvent));

    state = TouchGestureDetector::SlideState::DIRECTION_DOWN;
    GestureMode getureType = detector.ChangeToGestureMode(state);
    EXPECT_FALSE(detector.NotifyGestureEvent(pointerEvent, getureType));
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
    detector.downPoint_[3] = Point(5.0f, 7.0f);
    detector.downPoint_[4] = Point(7.0f, 8.0f);

    detector.lastDistance_[1] = 1.0;
    detector.lastDistance_[2] = 2.0;
    detector.lastDistance_[3] = 3.0;
    EXPECT_FALSE(detector.lastDistance_.empty());
    ASSERT_NO_FATAL_FAILURE(detector.HandlePinchMoveEvent(pointerEvent));
}
} // namespace MMI
} // namespace OHOS