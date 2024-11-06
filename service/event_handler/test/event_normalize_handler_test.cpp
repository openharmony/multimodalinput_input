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
#include <libinput.h>

#include "dfx_hisysevent.h"
#include "event_filter_handler.h"
#include "event_normalize_handler.h"
#include "event_resample.h"
#include "i_input_windows_manager.h"
#include "input_scene_board_judgement.h"
#include "input_device_manager.h"
#include "touchpad_transform_processor.h"

#include "libinput-private.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class EventNormalizeHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

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
    ASSERT_NO_FATAL_FAILURE(handler.HandleJoystickButtonEvent(event));
    event->type = LIBINPUT_EVENT_JOYSTICK_AXIS;
    handler.HandleEvent(event, frameTime);
    ASSERT_NO_FATAL_FAILURE(handler.HandleJoystickAxisEvent(event));
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
}
} // namespace MMI
} // namespace OHOS