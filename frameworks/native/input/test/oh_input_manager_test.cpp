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
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <utility>

#include "oh_input_manager.h"
#include "oh_key_code.h"
#include "input_manager.h"
#include "pointer_event.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputManagerTest"

struct Input_KeyState {
    int32_t keyCode;
    int32_t keyState;
    int32_t keySwitch;
};

struct Input_KeyEvent {
    int32_t id { -1 };
    int32_t action { -1 };
    int32_t keyCode { -1 };
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

struct Input_MouseEvent {
    int32_t action;
    int32_t displayX;
    int32_t displayY;
    int32_t globalX { INT32_MAX };
    int32_t globalY { INT32_MAX };
    int32_t button { -1 };
    int32_t axisType { -1 };
    float axisValue { 0.0f };
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

struct Input_TouchEvent {
    int32_t action;
    int32_t id;
    int32_t displayX;
    int32_t displayY;
    int32_t globalX { INT32_MAX };
    int32_t globalY { INT32_MAX };
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

struct Input_AxisEvent {
    int32_t axisAction;
    float displayX;
    float displayY;
    int32_t globalX;
    int32_t globalY;
    std::map<int32_t, double> axisValues;
    int64_t actionTime { -1 };
    int32_t sourceType;
    int32_t axisEventType { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};
static std::shared_ptr<OHOS::MMI::PointerEvent> g_touchEvent = OHOS::MMI::PointerEvent::Create();
static bool g_interceptorTriggered = false;
void MyKeyEventCallback(const Input_KeyEvent* keyEvent)
{
    if (keyEvent != nullptr) {
        g_interceptorTriggered = true;
    }
    return;
}
void DummyCallback(const Input_KeyEvent* keyEvent)
{
    return;
}

void HookCallback(const Input_KeyEvent* keyEvent)
{
    int32_t eventId { -1 };
    if (OH_Input_GetKeyEventId(keyEvent, &eventId) != INPUT_SUCCESS) {
        MMI_HILOGW("GetKeyEventId failed");
        return;
    }
    int32_t keyCode = OH_Input_GetKeyEventKeyCode(keyEvent);
    MMI_HILOGI("EventId:%{public}d, keyCode:%{private}d", eventId, keyCode);
}

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;

constexpr int32_t MIN_MULTI_TOUCH_POINT_NUM { 0 };
constexpr int32_t MAX_MULTI_TOUCH_POINT_NUM { 10 };
constexpr int32_t UNKNOWN_MULTI_TOUCH_POINT_NUM { -1 };
constexpr int32_t DEFAULT_GLOBAL_X { -1 };
constexpr int32_t DEFAULT_GLOBAL_Y { -1 };
constexpr int32_t REQUEST_INJECTION_TIME_MS { 4000 };
constexpr int32_t HOOK_WAIT_TIME_MS { 6000 };
} // namespace

class OHInputManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateKeyState
 * @tc.desc: Test the funcation OH_Input_CreateKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateKeyState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyState = OH_Input_CreateKeyState();
    EXPECT_EQ(keyState != nullptr, true);
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyKeyState(&keyState));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyState
 * @tc.desc: Test the funcation OH_Input_GetKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_KeyState inputKeyState;
    inputKeyState.keyCode = -1;
    EXPECT_EQ(OH_Input_GetKeyState(&inputKeyState), INPUT_PARAMETER_ERROR);
    inputKeyState.keyCode = 2123;
    EXPECT_EQ(OH_Input_GetKeyState(&inputKeyState), INPUT_PARAMETER_ERROR);
    inputKeyState.keyCode = 2018;
    EXPECT_EQ(OH_Input_GetKeyState(&inputKeyState), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyState_001
 * @tc.desc: Test the funcation OH_Input_GetKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyState_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyState inputKeyState;
    inputKeyState.keyCode = KEYCODE_F12;
    EXPECT_EQ(OH_Input_GetKeyState(&inputKeyState), INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectKeyEvent
 * @tc.desc: Test the funcation OH_Input_InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_KeyEvent inputKeyEvent;
    inputKeyEvent.keyCode = -1;
    EXPECT_EQ(OH_Input_InjectKeyEvent(&inputKeyEvent), INPUT_PARAMETER_ERROR);
    inputKeyEvent.keyCode = 2024;
    inputKeyEvent.actionTime = -1;
    inputKeyEvent.action = KEY_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectKeyEvent(&inputKeyEvent), INPUT_SUCCESS);
    inputKeyEvent.actionTime = 100;
    inputKeyEvent.action = KEY_ACTION_UP;
    EXPECT_EQ(OH_Input_InjectKeyEvent(&inputKeyEvent), INPUT_SUCCESS);
    inputKeyEvent.action = KEY_ACTION_CANCEL;
    EXPECT_EQ(OH_Input_InjectKeyEvent(&inputKeyEvent), INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectMouseEvent
 * @tc.desc: Test the funcation OH_Input_InjectMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectMouseEvent, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent inputMouseEvent;
    inputMouseEvent.actionTime = -1;
    inputMouseEvent.action = MOUSE_ACTION_CANCEL;
    inputMouseEvent.axisType = MOUSE_AXIS_SCROLL_VERTICAL;
    inputMouseEvent.button = MOUSE_BUTTON_NONE;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.actionTime = 100;
    inputMouseEvent.action = MOUSE_ACTION_MOVE;
    inputMouseEvent.axisType = MOUSE_AXIS_SCROLL_HORIZONTAL;
    inputMouseEvent.button = MOUSE_BUTTON_LEFT;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.action = MOUSE_ACTION_BUTTON_DOWN;
    inputMouseEvent.button = MOUSE_BUTTON_MIDDLE;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.action = MOUSE_ACTION_BUTTON_UP;
    inputMouseEvent.button = MOUSE_BUTTON_RIGHT;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.action = MOUSE_ACTION_AXIS_BEGIN;
    inputMouseEvent.button = MOUSE_BUTTON_FORWARD;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.action = MOUSE_ACTION_AXIS_UPDATE;
    inputMouseEvent.button = MOUSE_BUTTON_BACK;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.globalX = 300;
    inputMouseEvent.globalY = 300;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.globalX = INT32_MAX;
    inputMouseEvent.globalY = 300;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.globalX = 300;
    inputMouseEvent.globalY = INT32_MAX;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.globalX = INT32_MAX;
    inputMouseEvent.globalY = INT32_MAX;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = -1;
    inputTouchEvent.action = TOUCH_ACTION_CANCEL;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_001
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.displayX = -1;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_002
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = TOUCH_ACTION_MOVE;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_003
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = TOUCH_ACTION_UP;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_004
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = static_cast<Input_TouchEventAction>(10);
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_005
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.displayX = 300;
    inputTouchEvent.displayY = -1;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_006
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.displayX = 300;
    inputTouchEvent.displayY = 300;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_SUCCESS);

    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    inputTouchEvent.globalX = 300;
    inputTouchEvent.globalY = 300;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_SUCCESS);

    inputTouchEvent.globalX = INT32_MAX;
    inputTouchEvent.globalY = INT32_MAX;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_SUCCESS);

    inputTouchEvent.globalX = INT32_MAX;
    inputTouchEvent.globalY = 300;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_SUCCESS);

    inputTouchEvent.globalX = 300;
    inputTouchEvent.globalY = INT32_MAX;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DestroyAxisEvent
 * @tc.desc: Test the funcation OH_Input_DestroyAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DestroyAxisEvent, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_AxisEvent *inputAxisEvent = nullptr;
    EXPECT_EQ(OH_Input_DestroyAxisEvent(&inputAxisEvent), INPUT_PARAMETER_ERROR);
    delete inputAxisEvent;
    inputAxisEvent = nullptr;
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateMouseEvent
 * @tc.desc: Test the funcation OH_Input_CreateMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateMouseEvent, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateMouseEvent();
    EXPECT_EQ(event != nullptr, true);
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyMouseEvent(&event));
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyMouseEvent(nullptr));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DestroyAxisEvent_001
 * @tc.desc: Test the funcation OH_Input_DestroyAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DestroyAxisEvent_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_AxisEvent *inputAxisEvent = new (std::nothrow) Input_AxisEvent();
    ASSERT_NE(inputAxisEvent, nullptr);
    EXPECT_EQ(OH_Input_DestroyAxisEvent(&inputAxisEvent), INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetKeySwitch
 * @tc.desc: Test the funcation OH_Input_SetKeySwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetKeySwitch, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyState keyState;
    int32_t keySwitch = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeySwitch(nullptr, keySwitch));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeySwitch(&keyState, keySwitch));
    EXPECT_EQ(OH_Input_GetKeySwitch(nullptr), -1);
    EXPECT_EQ(OH_Input_GetKeySwitch(&keyState), 1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetKeyPressed
 * @tc.desc: Test the funcation OH_Input_SetKeyPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetKeyPressed, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyState keyState;
    int32_t keyAction = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyPressed(nullptr, keyAction));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyPressed(&keyState, keyAction));
    EXPECT_EQ(OH_Input_GetKeyPressed(&keyState), 1);
    EXPECT_EQ(OH_Input_GetKeyPressed(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyEventActionTime
 * @tc.desc: Test the funcation OH_Input_GetKeyEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyEventActionTime, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyEvent keyEvent;
    int32_t action = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventActionTime(nullptr, action));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventActionTime(&keyEvent, action));
    EXPECT_EQ(OH_Input_GetKeyEventActionTime(&keyEvent), 1);
    EXPECT_EQ(OH_Input_GetKeyEventActionTime(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyEventWindowId
 * @tc.desc: Test the funcation OH_Input_GetKeyEventWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyEventWindowId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyEvent keyEvent;
    int32_t action = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventWindowId(nullptr, action));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventWindowId(&keyEvent, action));
    EXPECT_EQ(OH_Input_GetKeyEventWindowId(&keyEvent), 1);
    EXPECT_EQ(OH_Input_GetKeyEventWindowId(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyEventDisplayId
 * @tc.desc: Test the funcation OH_Input_GetKeyEventDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyEventDisplayId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyEvent keyEvent;
    int32_t action = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventDisplayId(nullptr, action));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventDisplayId(&keyEvent, action));
    EXPECT_EQ(OH_Input_GetKeyEventDisplayId(&keyEvent), 1);
    EXPECT_EQ(OH_Input_GetKeyEventDisplayId(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyEventKeyCode
 * @tc.desc: Test the funcation OH_Input_GetKeyEventKeyCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyEventKeyCode, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyEvent keyEvent;
    int32_t keyCode = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventKeyCode(nullptr, keyCode));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventKeyCode(&keyEvent, keyCode));
    EXPECT_EQ(OH_Input_GetKeyEventKeyCode(&keyEvent), 1);
    EXPECT_EQ(OH_Input_GetKeyEventKeyCode(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventAction
 * @tc.desc: Test the funcation OH_Input_GetMouseEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventAction, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t action = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventAction(nullptr, action));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventAction(&event, action));
    EXPECT_EQ(OH_Input_GetMouseEventAction(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventAction(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventDisplayX
 * @tc.desc: Test the funcation OH_Input_GetMouseEventDisplayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventDisplayX, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t displayX = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventDisplayX(nullptr, displayX));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventDisplayX(&event, displayX));
    EXPECT_EQ(OH_Input_GetMouseEventDisplayX(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventDisplayX(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventDisplayY
 * @tc.desc: Test the funcation OH_Input_GetMouseEventDisplayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventDisplayY, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t displayY = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventDisplayY(nullptr, displayY));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventDisplayY(&event, displayY));
    EXPECT_EQ(OH_Input_GetMouseEventDisplayY(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventDisplayY(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventButton
 * @tc.desc: Test the funcation OH_Input_GetMouseEventButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventButton, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t button = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventButton(nullptr, button));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventButton(&event, button));
    EXPECT_EQ(OH_Input_GetMouseEventButton(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventButton(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventWindowId
 * @tc.desc: Test the funcation OH_Input_GetMouseEventWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventWindowId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t windowId = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventWindowId(nullptr, windowId));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventWindowId(&event, windowId));
    EXPECT_EQ(OH_Input_GetMouseEventWindowId(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventWindowId(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventDisplayId
 * @tc.desc: Test the funcation OH_Input_GetMouseEventDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventDisplayId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t displayId = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventDisplayId(nullptr, displayId));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventDisplayId(&event, displayId));
    EXPECT_EQ(OH_Input_GetMouseEventDisplayId(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventDisplayId(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventAxisType
 * @tc.desc: Test the funcation OH_Input_GetMouseEventAxisType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventAxisType, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t axisType = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventAxisType(nullptr, axisType));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventAxisType(&event, axisType));
    EXPECT_EQ(OH_Input_GetMouseEventAxisType(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventAxisType(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventActionTime
 * @tc.desc: Test the funcation OH_Input_GetMouseEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventActionTime, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    int32_t actionTime = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventActionTime(nullptr, actionTime));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventActionTime(&event, actionTime));
    EXPECT_EQ(OH_Input_GetMouseEventActionTime(&event), 1);
    EXPECT_EQ(OH_Input_GetMouseEventActionTime(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetMouseEventAxisValue
 * @tc.desc: Test the funcation OH_Input_GetMouseEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetMouseEventAxisValue, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent event;
    float axisValue = 1.0;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventAxisValue(nullptr, axisValue));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetMouseEventAxisValue(&event, axisValue));
    EXPECT_EQ(OH_Input_GetMouseEventAxisValue(&event), axisValue);
    EXPECT_EQ(OH_Input_GetMouseEventAxisValue(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyEventAction
 * @tc.desc: Test the funcation OH_Input_GetKeyEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyEventAction, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyEvent keyEvent;
    int32_t action = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventAction(nullptr, action));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyEventAction(&keyEvent, action));
    EXPECT_EQ(OH_Input_GetKeyEventAction(&keyEvent), 1);
    EXPECT_EQ(OH_Input_GetKeyEventAction(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetTouchEventFingerId
 * @tc.desc: Test the funcation OH_Input_GetTouchEventFingerId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetTouchEventFingerId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent event;
    int32_t id = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventFingerId(nullptr, id));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventFingerId(&event, id));
    EXPECT_EQ(OH_Input_GetTouchEventFingerId(&event), 1);
    EXPECT_EQ(OH_Input_GetTouchEventFingerId(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetTouchEventDisplayY
 * @tc.desc: Test the funcation OH_Input_GetTouchEventDisplayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetTouchEventDisplayY, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent event;
    int32_t displayX = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventDisplayY(nullptr, displayX));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventDisplayY(&event, displayX));
    EXPECT_EQ(OH_Input_GetTouchEventDisplayY(&event), 1);
    EXPECT_EQ(OH_Input_GetTouchEventDisplayY(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetTouchEventWindowId
 * @tc.desc: Test the funcation OH_Input_GetTouchEventWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetTouchEventWindowId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent event;
    int32_t windowId = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventWindowId(nullptr, windowId));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventWindowId(&event, windowId));
    EXPECT_EQ(OH_Input_GetTouchEventWindowId(&event), 1);
    EXPECT_EQ(OH_Input_GetTouchEventWindowId(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventAction
 * @tc.desc: Test the funcation OH_Input_GetAxisEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventAction, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventAction(nullptr, InputEvent_AxisAction::AXIS_ACTION_BEGIN));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventAction(event, InputEvent_AxisAction::AXIS_ACTION_BEGIN));
    InputEvent_AxisAction action;
    OH_Input_GetAxisEventAction(event, &action);
    EXPECT_EQ(action, InputEvent_AxisAction::AXIS_ACTION_BEGIN);
    EXPECT_EQ(OH_Input_GetAxisEventAction(nullptr, &action), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventAction(nullptr, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventAxisValue
 * @tc.desc: Test the funcation OH_Input_GetAxisEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventAxisValue, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    InputEvent_AxisType type = InputEvent_AxisType::AXIS_TYPE_PINCH;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventAxisValue(nullptr, type, 1));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventAxisValue(event, type, 1));
    double axisValue;
    OH_Input_GetAxisEventAxisValue(event, type, &axisValue);
    EXPECT_EQ(axisValue, 1);
    EXPECT_EQ(OH_Input_GetAxisEventAxisValue(nullptr, type, &axisValue), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventAxisValue(event, type, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventActionTime
 * @tc.desc: Test the funcation OH_Input_GetAxisEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventActionTime, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    int64_t actionTime = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventActionTime(nullptr, actionTime));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventActionTime(event, actionTime));
    actionTime = 0;
    OH_Input_GetAxisEventActionTime(event, &actionTime);
    EXPECT_EQ(actionTime, 1);
    EXPECT_EQ(OH_Input_GetAxisEventActionTime(nullptr, &actionTime), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventActionTime(event, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventType
 * @tc.desc: Test the funcation OH_Input_GetAxisEventType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventType, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    InputEvent_AxisEventType axisEventType = InputEvent_AxisEventType::AXIS_EVENT_TYPE_PINCH;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventType(nullptr, axisEventType));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventType(event, axisEventType));
    axisEventType = InputEvent_AxisEventType::AXIS_EVENT_TYPE_SCROLL;
    OH_Input_GetAxisEventType(event, &axisEventType);
    EXPECT_EQ(axisEventType, InputEvent_AxisEventType::AXIS_EVENT_TYPE_PINCH);
    EXPECT_EQ(OH_Input_GetAxisEventType(nullptr, &axisEventType), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventType(event, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventSourceType
 * @tc.desc: Test the funcation OH_Input_GetAxisEventSourceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventSourceType, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    InputEvent_SourceType type = InputEvent_SourceType::SOURCE_TYPE_TOUCHSCREEN;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventSourceType(nullptr, type));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventSourceType(event, type));
    type = InputEvent_SourceType::SOURCE_TYPE_MOUSE;
    OH_Input_GetAxisEventSourceType(event, &type);
    EXPECT_EQ(type, InputEvent_SourceType::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_EQ(OH_Input_GetAxisEventSourceType(nullptr, &type), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventSourceType(event, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventWindowId
 * @tc.desc: Test the funcation OH_Input_GetAxisEventWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventWindowId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    int32_t windowId = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventWindowId(nullptr, windowId));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventWindowId(event, windowId));
    windowId = 0;
    OH_Input_GetAxisEventWindowId(event, &windowId);
    EXPECT_EQ(windowId, 1);
    EXPECT_EQ(OH_Input_GetAxisEventWindowId(nullptr, &windowId), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventWindowId(event, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventDisplayId
 * @tc.desc: Test the funcation OH_Input_GetAxisEventDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventDisplayId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    int32_t displayId = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventDisplayId(nullptr, displayId));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventDisplayId(event, displayId));
    displayId = 0;
    OH_Input_GetAxisEventDisplayId(event, &displayId);
    EXPECT_EQ(displayId, 1);
    EXPECT_EQ(OH_Input_GetAxisEventDisplayId(nullptr, &displayId), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventDisplayId(event, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventGlobalX
 * @tc.desc: Test the funcation OH_Input_GetAxisEventGlobalX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventGlobalX, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    int32_t globalX = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventGlobalX(nullptr, globalX));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventGlobalX(event, globalX));
    globalX = 0;
    OH_Input_GetAxisEventGlobalX(event, &globalX);
    EXPECT_EQ(globalX, 1);
    EXPECT_EQ(OH_Input_GetAxisEventGlobalX(nullptr, &globalX), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventGlobalX(event, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventGlobalY
 * @tc.desc: Test the funcation OH_Input_GetAxisEventGlobalY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventGlobalY, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    int32_t globalY = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventGlobalY(nullptr, globalY));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventGlobalY(event, globalY));
    globalY = 0;
    OH_Input_GetAxisEventGlobalY(event, &globalY);
    EXPECT_EQ(globalY, 1);
    EXPECT_EQ(OH_Input_GetAxisEventGlobalY(nullptr, &globalY), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventGlobalY(event, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetIntervalSinceLastInput
 * @tc.desc: Test the funcation OH_Input_GetIntervalSinceLastInput
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetIntervalSinceLastInput, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    int64_t time = 1;
    EXPECT_EQ(OH_Input_GetIntervalSinceLastInput(nullptr), INPUT_PARAMETER_ERROR);
    EXPECT_NO_FATAL_FAILURE(OH_Input_GetIntervalSinceLastInput(&time));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveInputEventInterceptor
 * @tc.desc: Test the funcation OH_Input_RemoveInputEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveInputEventInterceptor, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveInputEventInterceptor());
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveKeyEventInterceptor());
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetRepeat
 * @tc.desc: Test the funcation OH_Input_GetRepeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetRepeat, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto key = OH_Input_CreateHotkey();
    bool isRepeat = true;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetRepeat(key, isRepeat));
    EXPECT_EQ(OH_Input_GetRepeat(nullptr, nullptr), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetRepeat(key, nullptr), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetRepeat(key, &isRepeat), INPUT_SUCCESS);
    OH_Input_DestroyHotkey(&key);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAllSystemHotkeys
 * @tc.desc: Test the funcation OH_Input_GetAllSystemHotkeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAllSystemHotkeys, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    int32_t count = 256;
    Input_Hotkey **key = OH_Input_CreateAllSystemHotkeys(count);
    EXPECT_EQ(OH_Input_GetAllSystemHotkeys(nullptr, nullptr), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAllSystemHotkeys(key, nullptr), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAllSystemHotkeys(key, &count), INPUT_SUCCESS);
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyAllSystemHotkeys(key, count));

    count = 3;
    auto keys = OH_Input_CreateAllSystemHotkeys(count);
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyAllSystemHotkeys(keys, count));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetFinalKey
 * @tc.desc: Test the funcation OH_Input_GetFinalKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetFinalKey, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *key = OH_Input_CreateHotkey();
    int32_t finalKey = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetFinalKey(nullptr, finalKey));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetFinalKey(key, finalKey));
    finalKey = 0;
    EXPECT_EQ(OH_Input_GetFinalKey(nullptr, nullptr), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetFinalKey(key, nullptr), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetFinalKey(key, &finalKey), INPUT_SUCCESS);
    OH_Input_DestroyHotkey(&key);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventMonitor
 * @tc.desc: Test the funcation OH_Input_AddKeyEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventMonitor_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyEventCallback callback1 = [](const Input_KeyEvent *keyEvent) {};
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddKeyEventMonitor(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddKeyEventMonitor(callback1));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveKeyEventMonitor(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveKeyEventMonitor(callback1));

    Input_MouseEventCallback callback2 = [](auto mouseEvent) {};
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddMouseEventMonitor(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddMouseEventMonitor(callback2));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveMouseEventMonitor(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveMouseEventMonitor(callback2));

    Input_TouchEventCallback callback3 = [](auto mouseEvent) {};
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddTouchEventMonitor(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddTouchEventMonitor(callback3));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveTouchEventMonitor(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveTouchEventMonitor(callback3));

    Input_AxisEventCallback callback4 = [](auto mouseEvent) {};
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddAxisEventMonitorForAll(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddAxisEventMonitorForAll(callback4));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveAxisEventMonitorForAll(nullptr));
    EXPECT_NO_FATAL_FAILURE(OH_Input_RemoveAxisEventMonitorForAll(callback4));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddAxisEventMonitor
 * @tc.desc: Test the funcation OH_Input_AddAxisEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddAxisEventMonitor, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    InputEvent_AxisEventType type = InputEvent_AxisEventType::AXIS_EVENT_TYPE_PINCH;
    EXPECT_EQ(OH_Input_AddAxisEventMonitor(type, nullptr), INPUT_PARAMETER_ERROR);
    auto callback = [](const Input_AxisEvent *axisEvent) {};
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddAxisEventMonitor(type, callback));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventDisplayY
 * @tc.desc: Test the funcation OH_Input_GetAxisEventDisplayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventDisplayY, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventDisplayY(nullptr, 1));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventDisplayY(event, 1));
    float displayY;
    OH_Input_GetAxisEventDisplayY(event, &displayY);
    EXPECT_EQ(displayY, 1);
    EXPECT_EQ(OH_Input_GetAxisEventDisplayY(nullptr, &displayY), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventDisplayY(nullptr, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventDisplayX
 * @tc.desc: Test the funcation OH_Input_GetAxisEventDisplayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventDisplayX, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventDisplayX(nullptr, 1));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetAxisEventDisplayX(event, 1));
    float displayX;
    OH_Input_GetAxisEventDisplayX(event, &displayX);
    EXPECT_EQ(displayX, 1);
    EXPECT_EQ(OH_Input_GetAxisEventDisplayX(nullptr, &displayX), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_GetAxisEventDisplayX(nullptr, nullptr), INPUT_PARAMETER_ERROR);
    OH_Input_DestroyAxisEvent(&event);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetTouchEventActionTime
 * @tc.desc: Test the funcation OH_Input_GetTouchEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetTouchEventActionTime, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent event;
    int64_t actionTime = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventActionTime(nullptr, actionTime));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventActionTime(&event, actionTime));
    EXPECT_EQ(OH_Input_GetTouchEventActionTime(&event), 1);
    EXPECT_EQ(OH_Input_GetTouchEventActionTime(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetTouchEventDisplayId
 * @tc.desc: Test the funcation OH_Input_GetTouchEventDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetTouchEventDisplayId, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent event;
    int32_t displayId = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventDisplayId(nullptr, displayId));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventDisplayId(&event, displayId));
    EXPECT_EQ(OH_Input_GetTouchEventDisplayId(&event), 1);
    EXPECT_EQ(OH_Input_GetTouchEventDisplayId(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetTouchEventDisplayX
 * @tc.desc: Test the funcation OH_Input_GetTouchEventDisplayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetTouchEventDisplayX, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent event;
    int32_t displayX = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventDisplayX(nullptr, displayX));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventDisplayX(&event, displayX));
    EXPECT_EQ(OH_Input_GetTouchEventDisplayX(&event), 1);
    EXPECT_EQ(OH_Input_GetTouchEventDisplayX(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetTouchEventAction
 * @tc.desc: Test the funcation OH_Input_GetTouchEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetTouchEventAction, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent event;
    int32_t action = 1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventAction(nullptr, action));
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetTouchEventAction(&event, action));
    EXPECT_EQ(OH_Input_GetTouchEventAction(&event), 1);
    EXPECT_EQ(OH_Input_GetTouchEventAction(nullptr), -1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateAxisEvent
 * @tc.desc: Test the funcation OH_Input_CreateAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateAxisEvent, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateAxisEvent();
    EXPECT_EQ(event != nullptr, true);
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyAxisEvent(&event));
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyAxisEvent(nullptr));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateKeyEvent
 * @tc.desc: Test the funcation OH_Input_CreateKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateKeyEvent, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateKeyEvent();
    EXPECT_EQ(event != nullptr, true);
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyKeyEvent(&event));
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyKeyEvent(nullptr));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateTouchEvent
 * @tc.desc: Test the funcation OH_Input_CreateTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateTouchEvent, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto event = OH_Input_CreateTouchEvent();
    EXPECT_EQ(event != nullptr, true);
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyTouchEvent(&event));
    EXPECT_NO_FATAL_FAILURE(OH_Input_DestroyTouchEvent(nullptr));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEventGlobal
 * @tc.desc: Test the funcation OH_Input_InjectTouchEventGlobal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEventGlobal, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent touchEvent;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(nullptr), INPUT_PARAMETER_ERROR);
    touchEvent.action = TOUCH_ACTION_DOWN;
    touchEvent.displayX = 1;
    touchEvent.displayY = 1;
    touchEvent.globalX = 1;
    touchEvent.globalY = 1;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PERMISSION_DENIED);

    touchEvent.globalX = INT32_MAX;
    touchEvent.globalY = INT32_MAX;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PARAMETER_ERROR);

    touchEvent.displayX = -1;
    touchEvent.displayY = -1;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PARAMETER_ERROR);

    touchEvent.action = -1;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetKeyCode
 * @tc.desc: Test the funcation OH_Input_SetKeyCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetKeyCode, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_KeyState keyState;
    int32_t keyCode = -1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyCode(&keyState, keyCode));
    keyCode = 2020;
    keyState.keyCode = 2300;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyCode(&keyState, keyCode));
    keyState.keyCode = KEYCODE_F1;
    EXPECT_NO_FATAL_FAILURE(OH_Input_SetKeyCode(&keyState, keyCode));
    const Input_KeyState keyState1 {.keyCode = KEYCODE_F1};
    EXPECT_EQ(OH_Input_GetKeyCode(&keyState1), KEYCODE_F1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RegisterDeviceListener
 * @tc.desc: Test the funcation OH_Input_RegisterDeviceListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RegisterDeviceListener, TestSize.Level2)
{
    auto listener1 = new (std::nothrow) Input_DeviceListener();
    if (listener1 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
    }
    listener1->deviceAddedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceAddedCallback1:deviceId:%{public}d", deviceId);
    };
    listener1->deviceRemovedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceRemovedCallback1:deviceId:%{public}d", deviceId);
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener1), INPUT_SUCCESS);

    auto listener2 = new (std::nothrow) Input_DeviceListener();
    if (listener2 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
    }
    listener2->deviceAddedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceAddedCallback2:deviceId:%{public}d", deviceId);
    };
    listener2->deviceRemovedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceRemovedCallback2:deviceId:%{public}d", deviceId);
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener2), INPUT_SUCCESS);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(listener1), INPUT_SUCCESS);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(listener2), INPUT_SUCCESS);
    delete listener1;
    delete listener2;
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_UnregisterDeviceListeners
 * @tc.desc: Test the funcation OH_Input_UnregisterDeviceListeners
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_UnregisterDeviceListeners, TestSize.Level1)
{
    auto listener1 = new (std::nothrow) Input_DeviceListener();
    if (listener1 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
    }
    listener1->deviceAddedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceAddedCallback1:deviceId:%{public}d", deviceId);
    };
    listener1->deviceRemovedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceRemovedCallback1:deviceId:%{public}d", deviceId);
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener1), INPUT_SUCCESS);

    auto listener2 = new (std::nothrow) Input_DeviceListener();
    if (listener2 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
    }
    listener2->deviceAddedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceAddedCallback2:deviceId:%{public}d", deviceId);
    };
    listener2->deviceRemovedCallback = [](int32_t deviceId) {
        MMI_HILOGI("deviceRemovedCallback2:deviceId:%{public}d", deviceId);
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener2), INPUT_SUCCESS);
    EXPECT_EQ(OH_Input_UnregisterDeviceListeners(), INPUT_SUCCESS);
    delete listener1;
    delete listener2;
}

/*
 * @tc.name: OHInputManagerTest_OH_Input_RegisterDeviceListener_Error
 * @tc.desc: Test the funcation OH_Input_RegisterDeviceListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RegisterDeviceListener_Error001, TestSize.Level1)
{
    Input_DeviceListener *listener = nullptr;
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(listener), INPUT_PARAMETER_ERROR);
}

/*
 * @tc.name: OHInputManagerTest_OH_Input_RegisterDeviceListener_Error
 * @tc.desc: Test the funcation OH_Input_RegisterDeviceListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RegisterDeviceListener_Error002, TestSize.Level1)
{
    Input_DeviceListener listener = {
        nullptr,
        nullptr,
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(&listener), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(&listener), INPUT_PARAMETER_ERROR);
}

/*
 * @tc.name: OHInputManagerTest_OH_Input_RegisterDeviceListener_Error
 * @tc.desc: Test the funcation OH_Input_RegisterDeviceListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RegisterDeviceListener_Error003, TestSize.Level3)
{
    Input_DeviceListener listener = {
        nullptr,
        [](int32_t deviceId) {},
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(&listener), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(&listener), INPUT_PARAMETER_ERROR);
}

/*
 * @tc.name: OHInputManagerTest_OH_Input_RegisterDeviceListener_Error
 * @tc.desc: Test the funcation OH_Input_RegisterDeviceListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RegisterDeviceListener_Error004, TestSize.Level1)
{
    Input_DeviceListener listener = {
        [](int32_t deviceId) {},
        nullptr,
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(&listener), INPUT_PARAMETER_ERROR);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(&listener), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceIds
 * @tc.desc: Test the funcation OH_Input_GetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceIds_001, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceIds
 * @tc.desc: Test the funcation OH_Input_GetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceIds_002, TestSize.Level1)
{
    const int32_t inSize = 1;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(outSize, 1);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceIds
 * @tc.desc: Test the funcation OH_Input_GetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceIds_003, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t *outSize = nullptr;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, outSize);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceIds
 * @tc.desc: Test the funcation OH_Input_GetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceIds_004, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t *deviceIds = nullptr;
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyboardType
 * @tc.desc: Test the funcation OH_Input_GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyboardType_001, TestSize.Level1)
{
    int32_t deviceId = 3;
    int32_t keyboardType = -1;
    Input_Result retResult = OH_Input_GetKeyboardType(deviceId, &keyboardType);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    MMI_HILOGD("keyboardType:%{public}d", keyboardType);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyboardType
 * @tc.desc: Test the funcation OH_Input_GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyboardType_002, TestSize.Level2)
{
    int32_t deviceId = 3;
    int32_t *keyboardType = nullptr;
    Input_Result retResult = OH_Input_GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyboardType
 * @tc.desc: Test the funcation OH_Input_GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyboardType_003, TestSize.Level2)
{
    int32_t deviceId = -1;
    int32_t keyboardType = -1;
    Input_Result retResult = OH_Input_GetKeyboardType(deviceId, &keyboardType);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyboardType
 * @tc.desc: Test the funcation OH_Input_GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyboardType_004, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize;
    int32_t keyboardType = -1;
    retResult = OH_Input_GetKeyboardType(deviceId, &keyboardType);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDevice
 * @tc.desc: Test the funcation OH_Input_GetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDevice_001, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDevice
 * @tc.desc: Test the funcation OH_Input_GetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDevice_002, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDevice
 * @tc.desc: Test the funcation OH_Input_GetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDevice_003, TestSize.Level1)
{
    int32_t deviceId = -1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    Input_Result retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDevice
 * @tc.desc: Test the funcation OH_Input_GetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDevice_004, TestSize.Level2)
{
    int32_t deviceId = 0;
    Input_DeviceInfo *deviceInfo = nullptr;
    Input_Result retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceName
 * @tc.desc: Test the funcation OH_Input_GetDeviceName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceName_001, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    char *name = nullptr;
    retResult = OH_Input_GetDeviceName(deviceInfo, &name);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_GT(std::strlen(name), 0);
    MMI_HILOGD("outSize:%{public}d", outSize);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceName
 * @tc.desc: Test the funcation OH_Input_GetDeviceName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceName_002, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = nullptr;
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    char *name = nullptr;
    retResult = OH_Input_GetDeviceName(deviceInfo, &name);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceName
 * @tc.desc: Test the funcation OH_Input_GetDeviceName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceName_003, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    char **name = nullptr;
    retResult = OH_Input_GetDeviceName(deviceInfo, name);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceName
 * @tc.desc: Test the funcation OH_Input_GetDeviceName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceName_004, TestSize.Level1)
{
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    char *name = nullptr;
    Input_Result retResult = OH_Input_GetDeviceName(deviceInfo, &name);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(std::strlen(name), 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceAddress
 * @tc.desc: Test the funcation OH_Input_GetDeviceAddress
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceAddress_001, TestSize.Level2)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    char *address = nullptr;
    retResult = OH_Input_GetDeviceAddress(deviceInfo, &address);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_GT(std::strlen(address), 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceAddress
 * @tc.desc: Test the funcation OH_Input_GetDeviceAddress
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceAddress_002, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = nullptr;
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);

    char *address = nullptr;
    retResult = OH_Input_GetDeviceAddress(deviceInfo, &address);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceAddress
 * @tc.desc: Test the funcation OH_Input_GetDeviceAddress
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceAddress_003, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    char **address = nullptr;
    retResult = OH_Input_GetDeviceAddress(deviceInfo, address);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceAddress
 * @tc.desc: Test the funcation OH_Input_GetDeviceAddress
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceAddress_004, TestSize.Level1)
{
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    char *address = nullptr;
    Input_Result retResult = OH_Input_GetDeviceAddress(deviceInfo, &address);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(std::strlen(address), 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceId
 * @tc.desc: Test the funcation OH_Input_GetDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceId_001, TestSize.Level2)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t id = -1;
    retResult = OH_Input_GetDeviceId(deviceInfo, &id);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    EXPECT_EQ(id, outSize - 1);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceId
 * @tc.desc: Test the funcation OH_Input_GetDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceId_002, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = nullptr;
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);

    int32_t id = -1;
    retResult = OH_Input_GetDeviceId(deviceInfo, &id);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceId
 * @tc.desc: Test the funcation OH_Input_GetDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceId_003, TestSize.Level2)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t *id = nullptr;
    retResult = OH_Input_GetDeviceId(deviceInfo, id);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceId
 * @tc.desc: Test the funcation OH_Input_GetDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceId_004, TestSize.Level1)
{
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    int32_t id = -1;
    Input_Result retResult = OH_Input_GetDeviceId(deviceInfo, &id);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_LT(id, 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetCapabilities
 * @tc.desc: Test the funcation OH_Input_GetCapabilities
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetCapabilities_001, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t capabilities = -1;
    retResult = OH_Input_GetCapabilities(deviceInfo, &capabilities);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetCapabilities
 * @tc.desc: Test the funcation OH_Input_GetCapabilities
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetCapabilities_002, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = nullptr;
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);

    int32_t capabilities = -1;
    retResult = OH_Input_GetCapabilities(deviceInfo, &capabilities);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetCapabilities
 * @tc.desc: Test the funcation OH_Input_GetCapabilities
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetCapabilities_003, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t *capabilities = nullptr;
    retResult = OH_Input_GetCapabilities(deviceInfo, capabilities);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetCapabilities
 * @tc.desc: Test the funcation OH_Input_GetCapabilities
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetCapabilities_004, TestSize.Level1)
{
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    int32_t capabilities = -1;
    Input_Result retResult = OH_Input_GetCapabilities(deviceInfo, &capabilities);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_LT(capabilities, 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVersion
 * @tc.desc: Test the funcation OH_Input_GetDeviceVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVersion_001, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t version = -1;
    retResult = OH_Input_GetDeviceVersion(deviceInfo, &version);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVersion
 * @tc.desc: Test the funcation OH_Input_GetDeviceVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVersion_002, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = nullptr;
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);

    int32_t version = -1;
    retResult = OH_Input_GetDeviceVersion(deviceInfo, &version);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVersion
 * @tc.desc: Test the funcation OH_Input_GetDeviceVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVersion_003, TestSize.Level3)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t *version = nullptr;
    retResult = OH_Input_GetDeviceVersion(deviceInfo, version);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVersion
 * @tc.desc: Test the funcation OH_Input_GetDeviceVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVersion_004, TestSize.Level2)
{
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    int32_t version = -1;
    Input_Result retResult = OH_Input_GetDeviceVersion(deviceInfo, &version);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_LT(version, 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceProduct
 * @tc.desc: Test the funcation OH_Input_GetDeviceProduct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceProduct_001, TestSize.Level2)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t product = -1;
    retResult = OH_Input_GetDeviceProduct(deviceInfo, &product);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceProduct
 * @tc.desc: Test the funcation OH_Input_GetDeviceProduct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceProduct_002, TestSize.Level2)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = nullptr;
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);

    int32_t product = -1;
    retResult = OH_Input_GetDeviceProduct(deviceInfo, &product);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceProduct
 * @tc.desc: Test the funcation OH_Input_GetDeviceProduct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceProduct_003, TestSize.Level2)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t *product = nullptr;
    retResult = OH_Input_GetDeviceProduct(deviceInfo, product);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceProduct
 * @tc.desc: Test the funcation OH_Input_GetDeviceProduct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceProduct_004, TestSize.Level1)
{
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    int32_t product = -1;
    Input_Result retResult = OH_Input_GetDeviceProduct(deviceInfo, &product);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_LT(product, 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVendor
 * @tc.desc: Test the funcation OH_Input_GetDeviceVendor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVendor_001, TestSize.Level2)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t vendor = -1;
    retResult = OH_Input_GetDeviceVendor(deviceInfo, &vendor);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVendor
 * @tc.desc: Test the funcation OH_Input_GetDeviceVendor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVendor_002, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = nullptr;
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);

    int32_t vendor = -1;
    retResult = OH_Input_GetDeviceVendor(deviceInfo, &vendor);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVendor
 * @tc.desc: Test the funcation OH_Input_GetDeviceVendor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVendor_003, TestSize.Level1)
{
    const int32_t inSize = 64;
    int32_t outSize = 0;
    int32_t deviceIds[inSize] = {0};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    int32_t deviceId = outSize - 1;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    int32_t *vendor = nullptr;
    retResult = OH_Input_GetDeviceVendor(deviceInfo, vendor);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceVendor
 * @tc.desc: Test the funcation OH_Input_GetDeviceVendor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceVendor_004, TestSize.Level1)
{
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    int32_t vendor = -1;
    Input_Result retResult = OH_Input_GetDeviceVendor(deviceInfo, &vendor);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_LT(vendor, 0);
    OH_Input_DestroyDeviceInfo(&deviceInfo);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DestroyDeviceInfo
 * @tc.desc: Test the funcation OH_Input_DestroyDeviceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DestroyDeviceInfo_001, TestSize.Level1)
{
    Input_DeviceInfo *deviceInfo = nullptr;
    OH_Input_DestroyDeviceInfo(&deviceInfo);
    EXPECT_EQ(deviceInfo, nullptr);
}

static void HotkeyCallback(Input_Hotkey *hotkey) {}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddHotkeyMonitor_001
 * @tc.desc: Duplicate subscription of identical hotkey will fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddHotkeyMonitor_001, TestSize.Level1)
{
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t preKeys[] {KEYCODE_CTRL_LEFT};
    OH_Input_SetPreKeys(hotkey, preKeys, sizeof(preKeys) / sizeof(int32_t));
    OH_Input_SetFinalKey(hotkey, KEYCODE_TAB);
    OH_Input_SetRepeat(hotkey, false);
    Input_Result result = OH_Input_AddHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, Input_Result::INPUT_SUCCESS);
    result = OH_Input_AddHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, Input_Result::INPUT_PARAMETER_ERROR);
    result = OH_Input_RemoveHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, Input_Result::INPUT_SUCCESS);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetFunctionKeyState_002
 * @tc.desc: Test the funcation OH_Input_GetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetFunctionKeyState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    int32_t state = -1;
    Input_Result retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    EXPECT_EQ(retResult, INPUT_KEYBOARD_DEVICE_NOT_EXIST);
    keyCode = -5;
    retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    keyCode = 5;
    retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_007
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.displayX = 300;
    inputTouchEvent.displayY = 300;
    inputTouchEvent.action = TOUCH_ACTION_UP;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), 0);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyboardType_005
 * @tc.desc: Test the funcation OH_Input_GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyboardType_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = -3;
    int32_t keyboardType = -1;
    Input_Result retResult = OH_Input_GetKeyboardType(deviceId, &keyboardType);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDevice_005
 * @tc.desc: Test the funcation OH_Input_GetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDevice_005, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = -5;
    Input_DeviceInfo *deviceInfo = OH_Input_CreateDeviceInfo();
    Input_Result retResult = OH_Input_GetDevice(deviceId, &deviceInfo);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceIds_005
 * @tc.desc: Test the funcation OH_Input_GetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceIds_005, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    const int32_t inSize = -5;
    int32_t outSize = 0;
    int32_t *deviceIds = nullptr;
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_UnregisterDeviceListeners();
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetPreKeys_001
 * @tc.desc: Test the funcation OH_Input_GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetPreKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t prekeys[2] = {KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT};
    OH_Input_SetPreKeys(hotkey, prekeys, 2);
    int32_t key = 0;
    int32_t key1 = 0;
    int32_t *pressedKeys[2] = {&key, &key1};
    int32_t pressedKeyNum = 0;
    Input_Result result = OH_Input_GetPreKeys(hotkey, pressedKeys, &pressedKeyNum);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetPreKeys_001
 * @tc.desc: Test the funcation OH_Input_SetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetPreKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t size = -5;
    int32_t prekeys[2] = {KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT};
    ASSERT_NO_FATAL_FAILURE(OH_Input_SetPreKeys(hotkey, prekeys, size));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateAllSystemHotkeys_001
 * @tc.desc: Test the funcation OH_Input_CreateAllSystemHotkeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateAllSystemHotkeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = -5;
    auto ret = OH_Input_CreateAllSystemHotkeys(count);
    EXPECT_EQ(ret, nullptr);
}

static void MouseEventCallback(const struct Input_MouseEvent *mouseEvent)
{
    EXPECT_NE(mouseEvent, nullptr);
    int32_t action = OH_Input_GetMouseEventAction(mouseEvent);
    int32_t displayX = OH_Input_GetMouseEventDisplayX(mouseEvent);
    int32_t displayY = OH_Input_GetMouseEventDisplayY(mouseEvent);
    MMI_HILOGI("MouseEventCallback, action:%{public}d, displayX:%{private}d, displayY:%{private}d",
        action, displayX, displayY);
}

static void TouchEventCallback(const struct Input_TouchEvent *touchEvent)
{
    EXPECT_NE(touchEvent, nullptr);
    int32_t action = OH_Input_GetTouchEventAction(touchEvent);
    int32_t id = OH_Input_GetTouchEventFingerId(touchEvent);
    MMI_HILOGI("TouchEventCallback, action:%{public}d, id:%{public}d", action, id);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectMouseEventGlobal
 * @tc.desc: Test the funcation OH_Input_InjectMouseEventGlobal
 * @tc.type: FUNC
 * @tc.require:nhj
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectMouseEventGlobal001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent inputMouseEvent;
    inputMouseEvent.actionTime = 1;
    inputMouseEvent.action = MOUSE_ACTION_CANCEL;
    inputMouseEvent.axisType = MOUSE_AXIS_SCROLL_VERTICAL;
    inputMouseEvent.button = MOUSE_BUTTON_LEFT;
    EXPECT_EQ(OH_Input_InjectMouseEventGlobal(&inputMouseEvent), INPUT_PARAMETER_ERROR);

    inputMouseEvent.actionTime = 100;
    inputMouseEvent.displayX = 300;
    inputMouseEvent.displayY = 300;
    inputMouseEvent.action = TOUCH_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectMouseEventGlobal(&inputMouseEvent), INPUT_PARAMETER_ERROR);

    inputMouseEvent.action = MOUSE_ACTION_AXIS_END;
    inputMouseEvent.button = static_cast<Input_MouseEventButton>(10);
    EXPECT_EQ(OH_Input_InjectMouseEventGlobal(&inputMouseEvent), INPUT_PARAMETER_ERROR);

    inputMouseEvent.actionTime = -1;
    inputMouseEvent.displayX = 300;
    inputMouseEvent.displayY = 300;
    inputMouseEvent.action = TOUCH_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectMouseEventGlobal(&inputMouseEvent), INPUT_PARAMETER_ERROR);

    inputMouseEvent.actionTime = 100;
    inputMouseEvent.globalX = 0;
    inputMouseEvent.globalY = 0;
    EXPECT_EQ(OH_Input_InjectMouseEventGlobal(&inputMouseEvent), INPUT_PARAMETER_ERROR);
}

static void KeyEventCallback(const struct Input_KeyEvent *keyEvent)
{
    EXPECT_NE(keyEvent, nullptr);
    int32_t action = OH_Input_GetKeyEventAction(keyEvent);
    int32_t id = OH_Input_GetKeyEventDisplayId(keyEvent);
    MMI_HILOGI("KeyEventCallback, action:%{public}d, id:%{public}d", action, id);
}

static void AxisEventCallback(const struct Input_AxisEvent *axisEvent)
{
    EXPECT_NE(axisEvent, nullptr);
    InputEvent_AxisAction axisAction = AXIS_ACTION_BEGIN;
    OH_Input_GetAxisEventAction(axisEvent, &axisAction);
    InputEvent_AxisEventType sourceType = AXIS_EVENT_TYPE_PINCH;
    OH_Input_GetAxisEventType(axisEvent, &sourceType);
    InputEvent_SourceType axisEventType = SOURCE_TYPE_MOUSE;
    OH_Input_GetAxisEventSourceType(axisEvent, &axisEventType);
    MMI_HILOGI("AxisEventCallback, axisAction:%{public}d, sourceType:%{public}d, axisEventType:%{public}d", axisAction,
        sourceType, axisEventType);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddInputEventInterceptor_001
 * @tc.desc: Test the funcation OH_Input_AddInputEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddInputEventInterceptor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_InterceptorEventCallback callback;
    callback.mouseCallback = MouseEventCallback;
    callback.touchCallback = TouchEventCallback;
    callback.axisCallback = AxisEventCallback;
    Input_InterceptorOptions *option = nullptr;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(SOURCE_TYPE_TOUCHSCREEN);
    Input_Result ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetSourceType(SOURCE_TYPE_MOUSE);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    Input_KeyEventCallback callback1 = [](auto event) {};
    EXPECT_EQ(OH_Input_AddKeyEventInterceptor(nullptr, option), INPUT_PARAMETER_ERROR);
    EXPECT_NO_FATAL_FAILURE(OH_Input_AddKeyEventInterceptor(callback1, option));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddInputEventInterceptor_002
 * @tc.desc: Test the funcation OH_Input_AddInputEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddInputEventInterceptor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_InterceptorEventCallback callback;
    callback.mouseCallback = MouseEventCallback;
    callback.touchCallback = TouchEventCallback;
    callback.axisCallback = AxisEventCallback;
    Input_InterceptorOptions *option = nullptr;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    Input_Result ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddInputEventInterceptor_003
 * @tc.desc: Test the funcation OH_Input_AddInputEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddInputEventInterceptor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_InterceptorEventCallback callback;
    callback.mouseCallback = MouseEventCallback;
    callback.touchCallback = TouchEventCallback;
    callback.axisCallback = AxisEventCallback;
    Input_InterceptorOptions *option = nullptr;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(SOURCE_TYPE_TOUCHPAD);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    Input_Result ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
}

/**
 * @tc.name: OHInputManagerTest_PointerEventMonitorCallback_001
 * @tc.desc: Test the funcation PointerEventMonitorCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_PointerEventMonitorCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_MouseEventCallback callback;
    callback = MouseEventCallback;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(SOURCE_TYPE_TOUCHSCREEN);
    Input_Result ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetSourceType(SOURCE_TYPE_MOUSE);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_PointerEventMonitorCallback_002
 * @tc.desc: Test the funcation PointerEventMonitorCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_PointerEventMonitorCallback_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_MouseEventCallback callback;
    callback = MouseEventCallback;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    Input_Result ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_PointerEventMonitorCallback_003
 * @tc.desc: Test the funcation PointerEventMonitorCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_PointerEventMonitorCallback_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_MouseEventCallback callback;
    callback = MouseEventCallback;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(SOURCE_TYPE_TOUCHPAD);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    Input_Result ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectMouseEvent
 * @tc.desc: Test the funcation OH_Input_InjectMouseEvent
 * @tc.type: FUNC
 * @tc.require:nhj
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectMouseEvent001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent inputMouseEvent;
    inputMouseEvent.actionTime = 1;
    inputMouseEvent.action = MOUSE_ACTION_CANCEL;
    inputMouseEvent.axisType = MOUSE_AXIS_SCROLL_VERTICAL;
    inputMouseEvent.button = MOUSE_BUTTON_LEFT;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.actionTime = 100;
    inputMouseEvent.displayX = 300;
    inputMouseEvent.displayY = 300;
    inputMouseEvent.action = TOUCH_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PERMISSION_DENIED);

    inputMouseEvent.action = MOUSE_ACTION_AXIS_END;
    inputMouseEvent.button = static_cast<Input_MouseEventButton>(10);
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_008, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = -100;
    inputTouchEvent.displayX = -1;
    inputTouchEvent.action = TOUCH_ACTION_DOWN;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.action = TOUCH_ACTION_UP;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    int32_t pointerId = 3;
    event->SetPointerId(pointerId);
    auto pointerIds = event->GetPointerIds();
    EXPECT_TRUE(pointerIds.empty());
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEvent_005
 * @tc.desc: Test the funcation OH_Input_InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent inputTouchEvent;
    inputTouchEvent.actionTime = 100;
    inputTouchEvent.displayX = 300;
    inputTouchEvent.displayY = -1;
    inputTouchEvent.action = TOUCH_ACTION_CANCEL;
    EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventMonitor
 * @tc.desc: Test the funcation OH_Input_AddKeyEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_KeyEventCallback callback;
    callback = KeyEventCallback;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    Input_Result retResult = OH_Input_RemoveKeyEventMonitor(callback);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    event->SetSourceType(SOURCE_TYPE_TOUCHSCREEN);
    Input_Result ret = OH_Input_AddKeyEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetSourceType(SOURCE_TYPE_MOUSE);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ret = OH_Input_AddKeyEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = OH_Input_AddKeyEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
    ret = OH_Input_AddKeyEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ret = OH_Input_AddKeyEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetFunctionKeyState_003
 * @tc.desc: Test the funcation OH_Input_GetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetFunctionKeyState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    int32_t state = 1;
    Input_Result retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    EXPECT_EQ(retResult, INPUT_KEYBOARD_DEVICE_NOT_EXIST);
    keyCode = -1;
    retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    keyCode = 5;
    retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    state = -1;
    retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetFunctionKeyState
 * @tc.desc: Test the funcation OH_Input_GetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetFunctionKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    int32_t state = -1;
    bool resultState = true;
    Input_Result retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
    int32_t napiCode = OHOS::MMI::InputManager::GetInstance()->GetFunctionKeyState(keyCode, resultState);
    EXPECT_EQ(napiCode, INPUT_KEYBOARD_DEVICE_NOT_EXIST);
    EXPECT_EQ(retResult, INPUT_KEYBOARD_DEVICE_NOT_EXIST);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyboardType
 * @tc.desc: Test the funcation OH_Input_GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyboardType_006, TestSize.Level2)
{
    int32_t deviceId = 0;
    int32_t keyboardType = 0;
    Input_Result ret = OH_Input_GetKeyboardType(deviceId, &keyboardType); // 假设 deviceId=0 是有效设备
    EXPECT_EQ(ret, INPUT_SUCCESS);
    EXPECT_NE(keyboardType, 0);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyboardType
 * @tc.desc: Test the funcation OH_Input_GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyboardType_007, TestSize.Level1)
{
    int32_t deviceId = 99999;
    int32_t keyboardType = -1;
    Input_Result retResult = OH_Input_GetKeyboardType(deviceId, &keyboardType);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetDeviceIds
 * @tc.desc: Test the funcation OH_Input_GetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetDeviceIds_006, TestSize.Level1)
{
    const int32_t inSize = 0;
    int32_t outSize = 1;
    int32_t deviceIds[inSize] = {};
    Input_Result retResult = OH_Input_GetDeviceIds(deviceIds, inSize, &outSize);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(outSize, 0);
}

/**
 * @tc.name: OHInputManagerTest_PointerEventMonitorCallback_004
 * @tc.desc: Test the funcation OH_Input_AddMouseEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_PointerEventMonitorCallback_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_MouseEventCallback callback;
    callback = MouseEventCallback;
    std::shared_ptr<OHOS::MMI::PointerEvent> event = OHOS::MMI::PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_PULL_DOWN);
    Input_Result ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_PULL_MOVE);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_PULL_UP);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    event->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_PULL_IN_WINDOW);
    ret = OH_Input_AddMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = OH_Input_RemoveMouseEventMonitor(callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/*
 * @tc.name: OHInputManagerTest_QueryMaxTouchPoints_001
 * @tc.desc: GetMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_QueryMaxTouchPoints_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto ret = OH_Input_QueryMaxTouchPoints(nullptr);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
}

/*
 * @tc.name: OHInputManagerTest_QueryMaxTouchPoints_002
 * @tc.desc: GetMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_QueryMaxTouchPoints_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointNum {UNKNOWN_MULTI_TOUCH_POINT_NUM};
    auto ret = OH_Input_QueryMaxTouchPoints(&pointNum);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    EXPECT_TRUE((pointNum == UNKNOWN_MULTI_TOUCH_POINT_NUM) ||
        ((pointNum >= MIN_MULTI_TOUCH_POINT_NUM) && (pointNum <= MAX_MULTI_TOUCH_POINT_NUM)));
}

/*
 * @tc.name: OHInputManagerTest_TouchMouseGlobalCoordinates
 * @tc.desc: OH_Input_SetTouchMouseGlobalX OH_Input_SetTouchMouseGlobalY
 * OH_Input_GetTouchMouseGlobalX OH_Input_GetMouseEventGlobalY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_TouchMouseGlobalCoordinates, TestSize.Level1)
{
    Input_MouseEvent mouseEvent;
    OH_Input_SetMouseEventGlobalX(&mouseEvent, DEFAULT_GLOBAL_X);
    OH_Input_SetMouseEventGlobalY(&mouseEvent, DEFAULT_GLOBAL_Y);
    int32_t globalX = OH_Input_GetMouseEventGlobalX(&mouseEvent);
    int32_t globalY = OH_Input_GetMouseEventGlobalY(&mouseEvent);
    EXPECT_TRUE((globalX == DEFAULT_GLOBAL_X) && (globalY == DEFAULT_GLOBAL_Y));
}

/*
 * @tc.name: OHInputManagerTest_TouchEventGlobalCoordinates
 * @tc.desc: OH_Input_SetTouchEventGlobalX OH_Input_SetTouchEventGlobalY
 * OH_Input_GetTouchEventGlobalX OH_Input_GetTouchEventGlobalY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_TouchEventGlobalCoordinates, TestSize.Level1)
{
    Input_TouchEvent touchEvent;
    OH_Input_SetTouchEventGlobalX(&touchEvent, DEFAULT_GLOBAL_X);
    OH_Input_SetTouchEventGlobalY(&touchEvent, DEFAULT_GLOBAL_Y);
    int32_t globalX = OH_Input_GetTouchEventGlobalX(&touchEvent);
    int32_t globalY = OH_Input_GetTouchEventGlobalY(&touchEvent);
    EXPECT_TRUE((globalX == DEFAULT_GLOBAL_X) && (globalY == DEFAULT_GLOBAL_Y));
}

/*
 * @tc.name: OHInputManagerTest_AxisEventGlobalCoordinates
 * @tc.desc: OH_Input_SetAxisEventGlobalX OH_Input_SetAxisEventGlobalY
 * OH_Input_GetAxisEventGlobalX OH_Input_GetAxisEventGlobalY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_AxisEventGlobalCoordinates, TestSize.Level1)
{
    Input_AxisEvent axisEvent;
    OH_Input_SetAxisEventGlobalX(&axisEvent, DEFAULT_GLOBAL_X);
    OH_Input_SetAxisEventGlobalY(&axisEvent, DEFAULT_GLOBAL_Y);
    int32_t globalX {0};
    int32_t globalY {0};
    ASSERT_EQ(OH_Input_GetAxisEventGlobalX(&axisEvent, &globalX), INPUT_SUCCESS);
    ASSERT_EQ(OH_Input_GetAxisEventGlobalY(&axisEvent, &globalY), INPUT_SUCCESS);
    EXPECT_TRUE((globalX == DEFAULT_GLOBAL_X) && (globalY == DEFAULT_GLOBAL_Y));
}

/**
 * @tc.name:  OHInputManagerTest_RequestInjection_001
 * @tc.desc: Verify the RequestInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_RequestInjection_001, TestSize.Level1)
{
    auto retResult = OH_Input_RequestInjection(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    retResult = OH_Input_QueryAuthorizedStatus(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    auto fnCallBack = [](Input_InjectionStatus authorizedStatus) {
        MMI_HILOGI("OH_Input_RequestInjection callbak:status:%{public}d", authorizedStatus);
    };
#ifndef OHOS_BUILD_PC_PRIORITY
    retResult = OH_Input_RequestInjection(fnCallBack);
    EXPECT_EQ(retResult, INPUT_DEVICE_NOT_SUPPORTED);
#endif
    Input_InjectionStatus status = Input_InjectionStatus::UNAUTHORIZED;
    InputManager::GetInstance()->Authorize(false);
    retResult = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(status, Input_InjectionStatus::UNAUTHORIZED);

    retResult = OH_Input_RequestInjection(fnCallBack);
    EXPECT_EQ(retResult, INPUT_DEVICE_NOT_SUPPORTED);

    retResult = OH_Input_RequestInjection(fnCallBack);

    retResult = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    InputManager::GetInstance()->Authorize(true);

    retResult = OH_Input_RequestInjection(fnCallBack);

    retResult = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(retResult, INPUT_SUCCESS);

    InputManager::GetInstance()->Authorize(false);
    OH_Input_CancelInjection();
    retResult = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(status, Input_InjectionStatus::UNAUTHORIZED);
}

/**
 * @tc.name:  OHInputManagerTest_RequestInjection_002
 * @tc.desc: Verify the RequestInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_RequestInjection_002, TestSize.Level1)
{
    Input_InjectionStatus status = Input_InjectionStatus::UNAUTHORIZED;
    auto retResult = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    auto fnCallBack = [](Input_InjectionStatus authorizedStatus) {
        MMI_HILOGI("OH_Input_RequestInjection callbak:status:%{public}d", authorizedStatus);
    };
    InputManager::GetInstance()->Authorize(false);
    OH_Input_CancelInjection();
    std::this_thread::sleep_for(std::chrono::milliseconds(REQUEST_INJECTION_TIME_MS));
    retResult = OH_Input_RequestInjection(fnCallBack);
    EXPECT_EQ(retResult, INPUT_DEVICE_NOT_SUPPORTED);
    InputManager::GetInstance()->Authorize(false);
    retResult = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(status, Input_InjectionStatus::UNAUTHORIZED);

    InputManager::GetInstance()->Authorize(false);
    retResult = OH_Input_RequestInjection(fnCallBack);

    retResult = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    EXPECT_EQ(status, Input_InjectionStatus::UNAUTHORIZED);
    InputManager::GetInstance()->Authorize(false);
    OH_Input_CancelInjection();
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEventGlobal_001
 * @tc.desc: Test the funcation OH_Input_InjectTouchEventGlobal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEventGlobal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(nullptr), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEventGlobal_002
 * @tc.desc: Test the funcation OH_Input_InjectTouchEventGlobal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEventGlobal_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent touchEvent;
    touchEvent.action = TOUCH_ACTION_DOWN;
    touchEvent.displayX = 100;
    touchEvent.displayY = 100;
    touchEvent.globalX = 100;
    touchEvent.globalY = 100;
    auto origin = g_touchEvent;
    g_touchEvent = nullptr;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PERMISSION_DENIED);
    g_touchEvent = origin;
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEventGlobal_003
 * @tc.desc: Test the funcation OH_Input_InjectTouchEventGlobal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEventGlobal_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent touchEvent;
    touchEvent.action = -1;
    touchEvent.displayX = 100;
    touchEvent.displayY = 100;
    touchEvent.globalX = 100;
    touchEvent.globalY = 100;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEventGlobal_004
 * @tc.desc: Test the funcation OH_Input_InjectTouchEventGlobal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEventGlobal_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent touchEvent;
    touchEvent.action = TOUCH_ACTION_DOWN;
    touchEvent.displayX = 100;
    touchEvent.displayY = 100;
    touchEvent.globalX = INT32_MAX;
    touchEvent.globalY = INT32_MAX;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectTouchEventGlobal_005
 * @tc.desc: Test the funcation OH_Input_InjectTouchEventGlobal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEventGlobal_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_TouchEvent touchEvent;
    touchEvent.action = TOUCH_ACTION_DOWN;
    touchEvent.displayX = 10;
    touchEvent.displayY = 10;
    touchEvent.globalX = 10;
    touchEvent.globalY = 10;
    EXPECT_EQ(OH_Input_InjectTouchEventGlobal(&touchEvent), INPUT_PERMISSION_DENIED);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_InjectMouseEventGlobal_002
 * @tc.desc: Test the funcation OH_Input_InjectMouseEventGlobal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectMouseEventGlobal_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent inputMouseEvent {};
    inputMouseEvent.actionTime = 100;
    inputMouseEvent.displayX = 300;
    inputMouseEvent.displayY = 300;
    inputMouseEvent.globalX = 300;
    inputMouseEvent.globalY = 300;
    inputMouseEvent.action = MOUSE_ACTION_BUTTON_DOWN;
    inputMouseEvent.button = MOUSE_BUTTON_LEFT;
    int32_t ret = OH_Input_InjectMouseEventGlobal(&inputMouseEvent);
    EXPECT_EQ(ret, INPUT_PERMISSION_DENIED);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventInterceptor_001
 * @tc.desc: Verify OH_Input_AddKeyEventInterceptor success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventInterceptor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_interceptorTriggered = false;
    InputManager::GetInstance()->Authorize(false);
    OH_Input_CancelInjection();
    Input_Result ret = OH_Input_AddKeyEventInterceptor(MyKeyEventCallback, nullptr);
    if (ret == INPUT_REPEAT_INTERCEPTOR) {
        MMI_HILOGI("[TEST] Interceptor already added");
        SUCCEED();
    }
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    EXPECT_FALSE(g_interceptorTriggered);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventInterceptor_002
 * @tc.desc: Verify duplicate OH_Input_AddKeyEventInterceptor fails with INPUT_REPEAT_INTERCEPTOR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventInterceptor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    (void)OH_Input_RemoveKeyEventInterceptor();
    Input_Result ret1 = OH_Input_AddKeyEventInterceptor(DummyCallback, nullptr);
    EXPECT_EQ(ret1, INPUT_SUCCESS);
    Input_Result ret2 = OH_Input_AddKeyEventInterceptor(DummyCallback, nullptr);
    EXPECT_EQ(ret2, INPUT_REPEAT_INTERCEPTOR);
    Input_Result retRm = OH_Input_RemoveKeyEventInterceptor();
    EXPECT_EQ(retRm, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddHotkeyMonitor_002
 * @tc.desc: Test AddHotkeyMonitor with nullptr parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddHotkeyMonitor_002, TestSize.Level1)
{
    Input_Result result = OH_Input_AddHotkeyMonitor(nullptr, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t preKeys[] { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, preKeys, sizeof(preKeys) / sizeof(int32_t));
    OH_Input_SetFinalKey(hotkey, KEYCODE_TAB);
    OH_Input_SetRepeat(hotkey, false);
    result = OH_Input_AddHotkeyMonitor(hotkey, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddHotkeyMonitor_003
 * @tc.desc: Test AddHotkeyMonitor system/other occupied and unsupported.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddHotkeyMonitor_003, TestSize.Level1)
{
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t preKeys[] { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, preKeys, sizeof(preKeys) / sizeof(int32_t));
    OH_Input_SetFinalKey(hotkey, KEYCODE_TAB);
    OH_Input_SetRepeat(hotkey, false);
    Input_Result result = OH_Input_AddHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_SUCCESS);
    result = OH_Input_RemoveHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_SUCCESS);
    result = OH_Input_AddHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_SUCCESS);
    result = OH_Input_RemoveHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_SUCCESS);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_001
 * @tc.desc: Return INPUT_PARAMETER_ERROR when hotkey is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_001, TestSize.Level1)
{
    Input_Result result = OH_Input_RemoveHotkeyMonitor(nullptr, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_002
 * @tc.desc: Return INPUT_PARAMETER_ERROR when callback is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_002, TestSize.Level1)
{
    Input_Hotkey* hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    Input_Result result = OH_Input_RemoveHotkeyMonitor(hotkey, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_003
 * @tc.desc: Return INPUT_PARAMETER_ERROR when MakeHotkeyInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_003, TestSize.Level1)
{
    Input_Hotkey* hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    Input_Result result = OH_Input_RemoveHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_004
 * @tc.desc: Return INPUT_SERVICE_EXCEPTION when DelEventCallback fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_004, TestSize.Level1)
{
    Input_Hotkey* hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    OH_Input_SetFinalKey(hotkey, 123);
    OH_Input_SetRepeat(hotkey, true);
    Input_Result result = OH_Input_RemoveHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_005
 * @tc.desc: Return INPUT_SUCCESS when unregistering a valid registered hotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveHotkeyMonitor_005, TestSize.Level1)
{
    Input_Hotkey* hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t preKeys[] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, preKeys, sizeof(preKeys) / sizeof(int32_t));
    OH_Input_SetFinalKey(hotkey, KEYCODE_TAB);
    OH_Input_SetRepeat(hotkey, false);
    Input_Result result = OH_Input_AddHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_SUCCESS);
    result = OH_Input_RemoveHotkeyMonitor(hotkey, &HotkeyCallback);
    EXPECT_EQ(result, INPUT_SUCCESS);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_QueryAuthorizedStatus_001
 * @tc.desc: Return INPUT_PARAMETER_ERROR when status is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_QueryAuthorizedStatus_001, TestSize.Level1)
{
    Input_Result result = OH_Input_QueryAuthorizedStatus(nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_QueryAuthorizedStatus_002
 * @tc.desc: Return success and valid status when service responds correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_QueryAuthorizedStatus_002, TestSize.Level1)
{
    Input_InjectionStatus status = Input_InjectionStatus::UNAUTHORIZED;
    Input_Result result = OH_Input_QueryAuthorizedStatus(&status);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_TRUE(status == Input_InjectionStatus::UNAUTHORIZED ||
                status == Input_InjectionStatus::AUTHORIZING ||
                status == Input_InjectionStatus::AUTHORIZED);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetPreKeys_002
 * @tc.desc: Return error when hotkey is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetPreKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t key0 = 0;
    int32_t *pressedKeys[1] = {&key0};
    int32_t pressedKeyNum = 0;
    Input_Result result = OH_Input_GetPreKeys(nullptr, pressedKeys, &pressedKeyNum);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetPreKeys_003
 * @tc.desc: Return error when preKeys is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetPreKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t pressedKeyNum = 0;
    Input_Result result = OH_Input_GetPreKeys(hotkey, nullptr, &pressedKeyNum);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetPreKeys_004
 * @tc.desc: Return error when *preKeys is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetPreKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t *pressedKeys[1] = {nullptr};
    int32_t pressedKeyNum = 0;
    Input_Result result = OH_Input_GetPreKeys(hotkey, pressedKeys, &pressedKeyNum);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetPreKeys_005
 * @tc.desc: Return error when preKeys set is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetPreKeys_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t key = 0;
    int32_t *pressedKeys[1] = {&key};
    int32_t pressedKeyNum = 0;
    Input_Result result = OH_Input_GetPreKeys(hotkey, pressedKeys, &pressedKeyNum);
    EXPECT_EQ(result, INPUT_SERVICE_EXCEPTION);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetPreKeys_006
 * @tc.desc: Return error when preKeyCount is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetPreKeys_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t key0 = 0;
    int32_t *pressedKeys[1] = {&key0};
    Input_Result result = OH_Input_GetPreKeys(hotkey, pressedKeys, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetPreKeys_002
 * @tc.desc: Verify that OH_Input_SetPreKeys handles nullptr hotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetPreKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t prekeys[2] = {KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT};
    ASSERT_NO_FATAL_FAILURE(OH_Input_SetPreKeys(nullptr, prekeys, 2));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetPreKeys_003
 * @tc.desc: Verify that OH_Input_SetPreKeys handles nullptr preKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetPreKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    ASSERT_NO_FATAL_FAILURE(OH_Input_SetPreKeys(hotkey, nullptr, 2));
    int32_t key = -1;
    int32_t *pressedKeys[1] = {&key};
    int32_t count = 0;
    Input_Result ret = OH_Input_GetPreKeys(hotkey, pressedKeys, &count);
    EXPECT_NE(ret, INPUT_SUCCESS);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetPreKeys_004
 * @tc.desc: Verify that OH_Input_SetPreKeys ignores size <= 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetPreKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);
    int32_t prekeys[2] = {KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT};
    ASSERT_NO_FATAL_FAILURE(OH_Input_SetPreKeys(hotkey, prekeys, 0));
    int32_t key = -1;
    int32_t *pressedKeys[1] = {&key};
    int32_t count = 0;
    Input_Result ret = OH_Input_GetPreKeys(hotkey, pressedKeys, &count);
    EXPECT_NE(ret, INPUT_SUCCESS);
    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAllSystemHotkeys_002
 * @tc.desc: Verify OH_Input_GetAllSystemHotkeys returns error when count is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAllSystemHotkeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey **hotkey = nullptr;
    Input_Result ret = OH_Input_GetAllSystemHotkeys(hotkey, nullptr);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAllSystemHotkeys_003
 * @tc.desc: Test the function OH_Input_GetAllSystemHotkeys with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAllSystemHotkeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = 0;
    Input_Result ret = OH_Input_GetAllSystemHotkeys(nullptr, &count);
    ASSERT_EQ(ret, INPUT_SUCCESS);
    ASSERT_GT(count, 0);
    Input_Hotkey **hotkey = OH_Input_CreateAllSystemHotkeys(count);
    ASSERT_NE(hotkey, nullptr);
    ret = OH_Input_GetAllSystemHotkeys(hotkey, &count);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    for (int i = 0; i < count; ++i) {
        ASSERT_NE(hotkey[i], nullptr);
    }

    // Step 5: Destroy hotkeys
    OH_Input_DestroyAllSystemHotkeys(hotkey, count);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateAllSystemHotkeys_002
 * @tc.desc: Test OH_Input_CreateAllSystemHotkeys with count not matching actual hotkeyCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateAllSystemHotkeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = 1000;
    auto ret = OH_Input_CreateAllSystemHotkeys(count);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_CreateAllSystemHotkeys_003
 * @tc.desc: Test OH_Input_CreateAllSystemHotkeys with correct count returned by GetAllSystemHotkeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_CreateAllSystemHotkeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t count = 0;
    Input_Result ret = OH_Input_GetAllSystemHotkeys(nullptr, &count);
    ASSERT_EQ(ret, INPUT_SUCCESS);
    ASSERT_GT(count, 0);
    Input_Hotkey **hotkeys = OH_Input_CreateAllSystemHotkeys(count);
    ASSERT_NE(hotkeys, nullptr);
    for (int i = 0; i < count; ++i) {
        ASSERT_NE(hotkeys[i], nullptr);
    }
    OH_Input_DestroyAllSystemHotkeys(hotkeys, count);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetIntervalSinceLastInput_002
 * @tc.desc: Verify OH_Input_GetIntervalSinceLastInput returns correct interval time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetIntervalSinceLastInput_002, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    int64_t interval = -1;
    int32_t result = OH_Input_GetIntervalSinceLastInput(&interval);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_GE(interval, 0);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveAxisEventMonitorForAll_001
 * @tc.desc: Test RemoveAxisEventMonitorForAll with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveAxisEventMonitorForAll_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_Result result = OH_Input_RemoveAxisEventMonitorForAll(nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveAxisEventMonitorForAll_002
 * @tc.desc: Test RemoveAxisEventMonitorForAll with callback not registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveAxisEventMonitorForAll_002, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto dummyCallback = [](const Input_AxisEvent* event) {};
    Input_Result result = OH_Input_RemoveAxisEventMonitorForAll(dummyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveAxisEventMonitorForAll_003
 * @tc.desc: Test RemoveAxisEventMonitorForAll with valid registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveAxisEventMonitorForAll_003, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto callback = [](const Input_AxisEvent* event) {};
    Input_Result addResult = OH_Input_AddAxisEventMonitorForAll(callback);
    EXPECT_EQ(addResult, INPUT_SUCCESS);
    Input_Result removeResult = OH_Input_RemoveAxisEventMonitorForAll(callback);
    EXPECT_EQ(removeResult, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveTouchEventMonitor_001
 * @tc.desc: Test RemoveTouchEventMonitor with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveTouchEventMonitor_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_Result result = OH_Input_RemoveTouchEventMonitor(nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveTouchEventMonitor_002
 * @tc.desc: Test RemoveTouchEventMonitor with callback not registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveTouchEventMonitor_002, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto dummyCallback = [](const Input_TouchEvent* event) {};
    Input_Result result = OH_Input_RemoveTouchEventMonitor(dummyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveTouchEventMonitor_003
 * @tc.desc: Test RemoveTouchEventMonitor after adding callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveTouchEventMonitor_003, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto callback = [](const Input_TouchEvent* event) {};
    Input_Result addResult = OH_Input_AddTouchEventMonitor(callback);
    EXPECT_EQ(addResult, INPUT_SUCCESS);
    Input_Result removeResult = OH_Input_RemoveTouchEventMonitor(callback);
    EXPECT_EQ(removeResult, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveMouseEventMonitor_001
 * @tc.desc: Test RemoveMouseEventMonitor with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveMouseEventMonitor_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    Input_Result result = OH_Input_RemoveMouseEventMonitor(nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveMouseEventMonitor_002
 * @tc.desc: Test RemoveMouseEventMonitor with callback not registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveMouseEventMonitor_002, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto dummyCallback = [](const Input_MouseEvent *event) {
        (void)event;
    };
    Input_Result result = OH_Input_RemoveMouseEventMonitor(dummyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveMouseEventMonitor_003
 * @tc.desc: Test RemoveMouseEventMonitor after adding a callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveMouseEventMonitor_003, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    auto mouseCallback = [](const Input_MouseEvent *event) {
        (void)event;
    };
    Input_Result addResult = OH_Input_AddMouseEventMonitor(mouseCallback);
    EXPECT_EQ(addResult, INPUT_SUCCESS);
    Input_Result removeResult = OH_Input_RemoveMouseEventMonitor(mouseCallback);
    EXPECT_EQ(removeResult, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveKeyEventMonitor_001
 * @tc.desc: Test RemoveKeyEventMonitor with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveKeyEventMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Result result = OH_Input_RemoveKeyEventMonitor(nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveKeyEventMonitor_002
 * @tc.desc: Test RemoveKeyEventMonitor with unregistered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveKeyEventMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto dummyCallback = [](const Input_KeyEvent *event) {
        (void)event;
    };
    Input_Result result = OH_Input_RemoveKeyEventMonitor(dummyCallback);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveKeyEventMonitor_003
 * @tc.desc: Test RemoveKeyEventMonitor after adding a callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveKeyEventMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyCallback = [](const Input_KeyEvent *event) {
        (void)event;
    };
    Input_Result addResult = OH_Input_AddKeyEventMonitor(keyCallback);
    EXPECT_EQ(addResult, INPUT_SUCCESS);
    Input_Result removeResult = OH_Input_RemoveKeyEventMonitor(keyCallback);
    EXPECT_EQ(removeResult, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddAxisEventMonitor_002
 * @tc.desc: Test AddAxisEventMonitor with valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddAxisEventMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputEvent_AxisEventType type = InputEvent_AxisEventType::AXIS_EVENT_TYPE_PINCH;
    auto callback = [](const Input_AxisEvent *axisEvent) {
        (void)axisEvent;
    };
    Input_Result result = OH_Input_AddAxisEventMonitor(type, callback);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddAxisEventMonitor_003
 * @tc.desc: Test AddAxisEventMonitor with same type and callback multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddAxisEventMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputEvent_AxisEventType type = InputEvent_AxisEventType::AXIS_EVENT_TYPE_SCROLL;
    auto callback = [](const Input_AxisEvent *axisEvent) {
        (void)axisEvent;
    };
    Input_Result result1 = OH_Input_AddAxisEventMonitor(type, callback);
    EXPECT_EQ(result1, INPUT_SUCCESS);
    Input_Result result2 = OH_Input_AddAxisEventMonitor(type, callback);
    EXPECT_EQ(result2, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddAxisEventMonitorForAll_001
 * @tc.desc: Test AddAxisEventMonitorForAll with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddAxisEventMonitorForAll_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(OH_Input_AddAxisEventMonitorForAll(nullptr), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddAxisEventMonitorForAll_002
 * @tc.desc: Test AddAxisEventMonitorForAll with valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddAxisEventMonitorForAll_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = [](const Input_AxisEvent *axisEvent) {
        (void)axisEvent;
    };
    Input_Result result = OH_Input_AddAxisEventMonitorForAll(callback);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddAxisEventMonitorForAll_003
 * @tc.desc: Test AddAxisEventMonitorForAll with same callback multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddAxisEventMonitorForAll_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = [](const Input_AxisEvent *axisEvent) {
        (void)axisEvent;
    };
    Input_Result firstResult = OH_Input_AddAxisEventMonitorForAll(callback);
    EXPECT_EQ(firstResult, INPUT_SUCCESS);
    Input_Result secondResult = OH_Input_AddAxisEventMonitorForAll(callback);
    EXPECT_EQ(secondResult, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddTouchEventMonitor_001
 * @tc.desc: Test AddTouchEventMonitor with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddTouchEventMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(OH_Input_AddTouchEventMonitor(nullptr), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddTouchEventMonitor_002
 * @tc.desc: Test AddTouchEventMonitor with valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddTouchEventMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = [](const Input_TouchEvent *touchEvent) {
        (void)touchEvent;
    };
    Input_Result result = OH_Input_AddTouchEventMonitor(callback);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddTouchEventMonitor_003
 * @tc.desc: Test AddTouchEventMonitor with same callback multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddTouchEventMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = [](const Input_TouchEvent *touchEvent) {
        (void)touchEvent;
    };
    Input_Result firstResult = OH_Input_AddTouchEventMonitor(callback);
    EXPECT_EQ(firstResult, INPUT_SUCCESS);
    Input_Result secondResult = OH_Input_AddTouchEventMonitor(callback);
    EXPECT_EQ(secondResult, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetKeyEventId_001
 * @tc.desc: Test OH_Input_GetKeyEventId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyEventId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_KeyEvent keyEvent;
    int32_t eventId { -1 };
    EXPECT_EQ(OH_Input_GetKeyEventId(&keyEvent, &eventId), INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventHook_001
 * @tc.desc: Test OH_Input_AddKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventHook_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Result ret = OH_Input_AddKeyEventHook(nullptr);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventHook_002
 * @tc.desc: Test OH_Input_AddKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventHook_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Result ret = OH_Input_AddKeyEventHook(HookCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = OH_Input_AddKeyEventHook(HookCallback);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    ret = OH_Input_RemoveKeyEventHook(HookCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventHook_003
 * @tc.desc: Test OH_Input_AddKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventHook_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Result ret = OH_Input_AddKeyEventHook(HookCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    auto testHook = [](const Input_KeyEvent* keyEvent) {};
    ret = OH_Input_AddKeyEventHook(testHook);
    EXPECT_EQ(ret, INPUT_REPEAT_INTERCEPTOR);
    ret = OH_Input_RemoveKeyEventHook(testHook);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = OH_Input_RemoveKeyEventHook(HookCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_AddKeyEventHook_004
 * @tc.desc: Test OH_Input_AddKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_AddKeyEventHook_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Result ret = OH_Input_AddKeyEventHook(HookCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(HOOK_WAIT_TIME_MS));
    ret = OH_Input_RemoveKeyEventHook(HookCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RemoveKeyEventHook_001
 * @tc.desc: Test OH_Input_RemoveKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RemoveKeyEventHook_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Result ret = OH_Input_RemoveKeyEventHook(nullptr);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
    auto testHook = [](const Input_KeyEvent* keyEvent) {};
    ret = OH_Input_RemoveKeyEventHook(testHook);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DispatchToNextHandler_001
 * @tc.desc: Test OH_Input_DispatchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DispatchToNextHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto numberHook = [] (const Input_KeyEvent* keyEvent) {
        static std::pair<int32_t, int32_t> numberKeyCodeRange { KEYCODE_0, KEYCODE_9 };
        static std::pair<int32_t, int32_t> numberPadKeyCodeRange { KEYCODE_NUMPAD_0, KEYCODE_NUMPAD_9 };
        CHKPV(keyEvent);
        int32_t eventId { -1 };
        if (OH_Input_GetKeyEventId(keyEvent, &eventId) != INPUT_SUCCESS) {
            MMI_HILOGW("GetEventId failed");
            return;
        }
        int32_t keyCode = OH_Input_GetKeyEventKeyCode(keyEvent);
        int32_t keyAction = OH_Input_GetKeyEventAction(keyEvent);
        MMI_HILOGI("EventId:%{public}d, keyCode:%{private}d", eventId, keyCode);
        if ((keyCode >= numberKeyCodeRange.first && keyCode <= numberKeyCodeRange.second) ||
            (keyCode >= numberPadKeyCodeRange.first && keyCode <= numberPadKeyCodeRange.second)) {
            MMI_HILOGI("Accept number eventId:%{public}d, keyCode:%{private}d, keyAction:%{public}d",
                eventId, keyCode, keyAction);
        } else {
            int32_t ret = OH_Input_DispatchToNextHandler(eventId);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        }
    };
    Input_Result ret = OH_Input_AddKeyEventHook(numberHook);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(HOOK_WAIT_TIME_MS));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DispatchToNextHandler_002
 * @tc.desc: Test OH_Input_DispatchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DispatchToNextHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto alphabetHook = [](const Input_KeyEvent* keyEvent) {
        static std::pair<int32_t, int32_t> alphabetKeyCodeRange { KEYCODE_A, KEYCODE_Z };
        CHKPV(keyEvent);
        int32_t eventId { -1 };
        if (OH_Input_GetKeyEventId(keyEvent, &eventId) != INPUT_SUCCESS) {
            MMI_HILOGW("GetEventId failed");
        }
        int32_t keyCode = OH_Input_GetKeyEventKeyCode(keyEvent);
        int32_t keyAction = OH_Input_GetKeyEventAction(keyEvent);
        MMI_HILOGI("EventId:%{public}d, keyCode:%{private}d", eventId, keyCode);
        if (keyCode >= alphabetKeyCodeRange.first && keyCode <= alphabetKeyCodeRange.second) {
            MMI_HILOGI("Accept alphabet eventId:%{public}d, keyCode:%{private}d, keyAction:%{public}d",
                eventId, keyCode, keyAction);
        } else {
            int32_t ret = OH_Input_DispatchToNextHandler(eventId);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        }
    };
    Input_Result ret = OH_Input_AddKeyEventHook(alphabetHook);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(HOOK_WAIT_TIME_MS));
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DispatchToNextHandler_003
 * @tc.desc: Test OH_Input_DispatchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DispatchToNextHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Result ret = OH_Input_DispatchToNextHandler(1);
    EXPECT_NE(ret, INPUT_SUCCESS);
}
} // namespace MMI
} // namespace OHOS