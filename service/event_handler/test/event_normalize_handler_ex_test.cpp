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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dfx_hisysevent.h"
#include "event_filter_handler.h"
#include "event_normalize_handler.h"
#include "event_resample.h"
#include "general_touchpad.h"
#include "gesture_handler.h"
#include "input_device_manager.h"
#include "libinput_mock.h"
#include "libinput_wrapper.h"
#include "i_input_windows_manager.h"
#include "mouse_event_normalize.h"
#include "tablet_tool_tranform_processor.h"
#include "touchpad_transform_processor.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventNormalizeHandlerEXTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
} // namespace

class EventNormalizeHandlerEXTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void EventNormalizeHandlerEXTest::SetUpTestCase(void)
{
}

void EventNormalizeHandlerEXTest::TearDownTestCase(void)
{
}

void EventNormalizeHandlerEXTest::SetUp()
{
}

void EventNormalizeHandlerEXTest::TearDown()
{
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_GestureIdentify_001
 * @tc.desc: Test the function GestureIdentify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_GestureIdentify_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    libinput_event event {};
    libinput_event_touch touchevent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchevent));
    libinput_device device {};
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&device));
    ASSERT_NO_FATAL_FAILURE(handler.GestureIdentify(&event));
    MouseEventNormalize mouseEventNormalize;
    mouseEventNormalize.processors_.insert(std::make_pair(1, nullptr));
    ASSERT_NO_FATAL_FAILURE(handler.GestureIdentify(&event));
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_TerminateAxis_001
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_TerminateAxis_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateAxis(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateAxis(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_AXIS));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateAxis(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_TAP));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateAxis(&event));
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_TerminateRotate_001
 * @tc.desc: Test the function TerminateRotate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_TerminateRotate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    GestureHandler gestureHandler;
    gestureHandler.isStartRotate_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.TerminateRotate(&event));
    gestureHandler.isStartRotate_ = true;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateRotate(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateRotate(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_AXIS));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateRotate(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_TAP));
    ASSERT_NO_FATAL_FAILURE(handler.TerminateRotate(&event));
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_ResetTouchUpEvent_001
 * @tc.desc: Test the function ResetTouchUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_ResetTouchUpEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCH_UP));
    ASSERT_NO_FATAL_FAILURE(handler.ResetTouchUpEvent(pointerEvent, &event));
    PointerEvent::PointerItem testPointerItem;
    pointerEvent->pointers_.push_back(PointerEvent::PointerItem());
    ASSERT_NO_FATAL_FAILURE(handler.ResetTouchUpEvent(pointerEvent, &event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCH_DOWN));
    ASSERT_NO_FATAL_FAILURE(handler.ResetTouchUpEvent(pointerEvent, &event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCH_MOTION));
    ASSERT_NO_FATAL_FAILURE(handler.ResetTouchUpEvent(pointerEvent, &event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCH_CANCEL));
    ASSERT_NO_FATAL_FAILURE(handler.ResetTouchUpEvent(pointerEvent, &event));
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandleMouseEvent_001
 * @tc.desc: Test the function HandleMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandleMouseEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_device device {};
    libinput_event_pointer pointerEvent {};
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&device));
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(const_cast<char*>("rotary_crown")));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_AXIS));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(&pointerEvent));
    EXPECT_CALL(libinputMock, GetAxisSource).WillRepeatedly(Return(LIBINPUT_POINTER_AXIS_SOURCE_WHEEL));
    ASSERT_NO_FATAL_FAILURE(handler.HandleMouseEvent(&event));
    EXPECT_CALL(libinputMock, GetAxisSource).WillRepeatedly(Return(LIBINPUT_POINTER_AXIS_SOURCE_FINGER));
    ASSERT_NO_FATAL_FAILURE(handler.HandleMouseEvent(&event));
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandleGestureEvent_001
 * @tc.desc: Test the function HandleGestureEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandleGestureEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    handler.nextHandler_ = std::make_shared<EventFilterHandler>();
    handler.SetNext(handler.nextHandler_);
    libinput_event event {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_device device {};
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&device));
    MouseEventNormalize mouseEventNormalize;
    mouseEventNormalize.processors_.insert(std::make_pair(1, nullptr));
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 2;
    inDevice.isPointerDevice = false;
    inDevice.enable = false;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, inDevice));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_GESTURE_SWIPE_END));
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_GESTURE_PINCH_END));
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(&event));
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem testPointerItem;
    pointerEvent->pointers_.push_back(PointerEvent::PointerItem());
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE));
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN));
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_GESTURE_PINCH_UPDATE));
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(&event));
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandlePalmEvent_001
 * @tc.desc: Test the function HandlePalmEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandlePalmEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    libinput_event event {};
    libinput_event_touch touchevent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(nullptr));
    ASSERT_NO_FATAL_FAILURE(handler.HandlePalmEvent(&event, pointerEvent));
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchevent));
    EXPECT_CALL(libinputMock, TouchpadGetTool).WillRepeatedly(Return(2));
    ASSERT_NO_FATAL_FAILURE(handler.HandlePalmEvent(&event, pointerEvent));
    EXPECT_CALL(libinputMock, TouchpadGetTool).WillRepeatedly(Return(3));
    ASSERT_NO_FATAL_FAILURE(handler.HandlePalmEvent(&event, pointerEvent));
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandleTouchPadEvent_001
 * @tc.desc: Test the function HandleTouchPadEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandleTouchPadEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    int32_t deviceId = 6;
    TabletToolTransformProcessor tabletToolTransformProcessor(deviceId);
    tabletToolTransformProcessor.pointerEvent_ = PointerEvent::Create();
    libinput_event event {};
    handler.nextHandler_ = std::make_shared<EventFilterHandler>();
    handler.SetNext(handler.nextHandler_);
    libinput_event_touch touchevent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchevent));
    MultiFingersTapHandler processor;
    processor.multiFingersState_ = MulFingersTap::TRIPLETAP;
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchPadEvent(&event));
    processor.multiFingersState_ = MulFingersTap::QUADTAP;
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchPadEvent(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_DOWN));
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchPadEvent(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_UP));
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchPadEvent(&event));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_MOTION));
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchPadEvent(&event));
}
} // namespace MMI
} // namespace OHOS