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

#include "display_manager.h"

#include "dfx_hisysevent.h"
#include "event_filter_handler.h"
#include "event_normalize_handler.h"
#include "event_resample.h"
#include "general_touchpad.h"
#include "input_device_manager.h"
#include "input_scene_board_judgement.h"
#include "i_input_windows_manager.h"
#include "libinput_wrapper.h"
#include "touchpad_transform_processor.h"

#include "libinput-private.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class EventNormalizeHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void UpdateDisplayInfo();

private:
    static void SetupTouchpad();
    static void CloseTouchpad();
    static GeneralTouchpad vTouchpad_;
    static LibinputWrapper libinput_;
    int32_t trackingID_ { 0 };
};

GeneralTouchpad EventNormalizeHandlerTest::vTouchpad_;
LibinputWrapper EventNormalizeHandlerTest::libinput_;

void EventNormalizeHandlerTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupTouchpad();
    UpdateDisplayInfo();
}

void EventNormalizeHandlerTest::TearDownTestCase(void)
{
    CloseTouchpad();
}

void EventNormalizeHandlerTest::SetupTouchpad()
{
    ASSERT_TRUE(vTouchpad_.SetUp());
    std::cout << "device node name: " << vTouchpad_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vTouchpad_.GetDevPath()));
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
    struct libinput_device *device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
    INPUT_DEV_MGR->OnInputDeviceAdded(device);
}

void EventNormalizeHandlerTest::CloseTouchpad()
{
    libinput_.RemovePath(vTouchpad_.GetDevPath());
    vTouchpad_.Close();
}

void EventNormalizeHandlerTest::UpdateDisplayInfo()
{
    auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    ASSERT_TRUE(display != nullptr);
    DisplayGroupInfo displays {
        .width = display->GetWidth(),
        .height = display->GetHeight(),
        .focusWindowId = -1,
    };
    displays.displaysInfo.push_back(DisplayInfo {
        .name = "default display",
        .width = display->GetWidth(),
        .height = display->GetHeight(),
    });
    WIN_MGR->UpdateDisplayInfo(displays);
}
/**
 * @tc.name: EventNormalizeHandlerTest_HandleEvent_002
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandleEvent_002, TestSize.Level1)
{
    EventNormalizeHandler handler;
    int64_t frameTime = 10000;
    libinput_event* event = new (std::nothrow) libinput_event;
    ASSERT_NE(event, nullptr);
    event->type = LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(event));
    event->type = LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(event));
    event->type = LIBINPUT_EVENT_GESTURE_SWIPE_END;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(event));
    event->type = LIBINPUT_EVENT_GESTURE_PINCH_UPDATE;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(event));
    event->type = LIBINPUT_EVENT_GESTURE_PINCH_END;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleGestureEvent(event));
    event->type = LIBINPUT_EVENT_TOUCH_DOWN;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_TOUCH_UP;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_TOUCH_MOTION;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_TABLET_TOOL_AXIS;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTableToolEvent(event));
    event->type = LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTableToolEvent(event));
    event->type = LIBINPUT_EVENT_TABLET_TOOL_TIP;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTableToolEvent(event));
    event->type = LIBINPUT_EVENT_JOYSTICK_BUTTON;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleJoystickEvent(event));
    event->type = LIBINPUT_EVENT_JOYSTICK_AXIS;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleJoystickEvent(event));
    event->type = LIBINPUT_EVENT_SWITCH_TOGGLE;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleSwitchInputEvent(event));
}

/**
 * @tc.name: EventNormalizeHandlerTest_ProcessNullEvent_001
 * @tc.desc: Test the function ProcessNullEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_ProcessNullEvent_001, TestSize.Level1)
{
    EventNormalizeHandler handler;
    int64_t frameTime = 10000;
    libinput_event* event = nullptr;
    EventResampleHdr->pointerEvent_ = PointerEvent::Create();
    bool ret = handler.ProcessNullEvent(event, frameTime);
    ASSERT_FALSE(ret);
    event = new (std::nothrow) libinput_event;
    ASSERT_NE(event, nullptr);
    event->type = LIBINPUT_EVENT_NONE;
    ret = handler.ProcessNullEvent(event, frameTime);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventNormalizeHandlerTest_HandleKeyEvent_001
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandleKeyEvent_001, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetRepeat(true);
    EventNormalizeHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
    keyEvent->SetRepeat(false);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventNormalizeHandlerTest_HandlePointerEvent_001
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandlePointerEvent_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EventNormalizeHandler handler;
    handler.nextHandler_ = std::make_shared<EventFilterHandler>();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent->UpdatePointerItem(0, item);
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventNormalizeHandlerTest_HandleTouchEvent_001
 * @tc.desc: Test the function HandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandleTouchEvent_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EventNormalizeHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(pointerEvent));
    pointerEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventNormalizeHandlerTest_UpdateKeyEventHandlerChain_001
 * @tc.desc: Test the function UpdateKeyEventHandlerChain
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_UpdateKeyEventHandlerChain_001, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EventNormalizeHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.UpdateKeyEventHandlerChain(keyEvent));
    keyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.UpdateKeyEventHandlerChain(keyEvent));
}

/**
 * @tc.name: EventNormalizeHandlerTest_SetOriginPointerId_001
 * @tc.desc: Test the function SetOriginPointerId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_SetOriginPointerId_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EventNormalizeHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.SetOriginPointerId(pointerEvent));
    pointerEvent = nullptr;
    int32_t ret = handler.SetOriginPointerId(pointerEvent);
    pointerEvent = nullptr;
    ASSERT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: EventNormalizeHandlerTest_HandlePalmEvent
 * @tc.desc: Test the function HandlePalmEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandlePalmEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 715);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    EXPECT_NO_FATAL_FAILURE(handler.HandlePalmEvent(event, pointerEvent));
}

/**
 * @tc.name: EventNormalizeHandlerTest_GestureIdentify
 * @tc.desc: Test the function GestureIdentify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_GestureIdentify, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2100);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 690);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 713);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    ASSERT_EQ(handler.GestureIdentify(event), RET_ERR);
}

/**
 * @tc.name: EventNormalizeHandlerTest_HandleTouchEvent
 * @tc.desc: Test the function HandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandleTouchEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    int64_t frameTime = 10000;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 958);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 896);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 712);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    handler.nextHandler_ = std::make_shared<EventFilterHandler>();
    handler.SetNext(handler.nextHandler_);
    ASSERT_NE(handler.HandleTouchEvent(event, frameTime), RET_OK);
}

/**
 * @tc.name: EventNormalizeHandlerTest_ResetTouchUpEvent
 * @tc.desc: Test the function ResetTouchUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_ResetTouchUpEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 729);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 562);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 711);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(handler.ResetTouchUpEvent(pointerEvent, event));
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(handler.ResetTouchUpEvent(pointerEvent, event));
}

/**
 * @tc.name: EventNormalizeHandlerTest_TerminateAxis
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_TerminateAxis, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 723);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 693);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    handler.nextHandler_ = std::make_shared<EventFilterHandler>();
    handler.SetNext(handler.nextHandler_);
    EXPECT_NO_FATAL_FAILURE(handler.TerminateAxis(event));
}

/**
 * @tc.name: EventNormalizeHandlerTest_ProcessNullEvent_002
 * @tc.desc: Test the function ProcessNullEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_ProcessNullEvent_002, TestSize.Level1)
{
    EventNormalizeHandler handler;
    int64_t frameTime = 100;
    libinput_event* event = nullptr;
    EventResampleHdr->pointerEvent_ = PointerEvent::Create();
    MMISceneBoardJudgement judgement;
    judgement.IsSceneBoardEnabled();
    judgement.IsResampleEnabled();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    bool ret = handler.ProcessNullEvent(event, frameTime);
    ASSERT_FALSE(ret);
    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_TOUCHPAD;
    ret = handler.ProcessNullEvent(event, frameTime);
    ASSERT_FALSE(ret);
    pointerEvent->sourceType_ = PointerEvent::SOURCE_TYPE_JOYSTICK;
    ret = handler.ProcessNullEvent(event, frameTime);
    ASSERT_FALSE(ret);
    EventResampleHdr->pointerEvent_ = nullptr;
    ret = handler.ProcessNullEvent(event, frameTime);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EventNormalizeHandlerTest_HandleEvent_001
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandleEvent_001, TestSize.Level1)
{
    EventNormalizeHandler handler;
    MultiFingersTapHandler processor;
    int64_t frameTime = 100;
    libinput_event* event = new (std::nothrow) libinput_event;
    ASSERT_NE(event, nullptr);
    event->type = LIBINPUT_EVENT_TOUCH_CANCEL;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_TOUCH_FRAME;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_TAP;
    processor.multiFingersState_ = MulFingersTap::TRIPLETAP;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    processor.multiFingersState_ = MulFingersTap::NO_TAP;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_DEVICE_ADDED;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_DEVICE_REMOVED;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_KEYBOARD_KEY;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_MOTION;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_BUTTON;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_AXIS;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_TAP;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_TOUCHPAD_UP;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_NONE;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_GESTURE_PINCH_BEGIN;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
    event->type = LIBINPUT_EVENT_GESTURE_SWIPE_END;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(event, frameTime));
}

/**
 * @tc.name: EventNormalizeHandlerTest_HandleKeyboardEvent_001
 * @tc.desc: Test the function HandleKeyboardEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTest, EventNormalizeHandlerTest_HandleKeyboardEvent_001, TestSize.Level1)
{
    EventNormalizeHandler handler;
    libinput_event* event = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyboardEvent(event));
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pressedKeys_.push_back(1);
    pointerEvent->pressedKeys_.push_back(2);
    pointerEvent->pressedKeys_.push_back(3);
    pointerEvent->pressedKeys_.push_back(4);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyboardEvent(event));
    event = new (std::nothrow) libinput_event;
    ASSERT_NE(event, nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyboardEvent(event));
}
} // namespace MMI
} // namespace OHOS