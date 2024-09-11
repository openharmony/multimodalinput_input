/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "input_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "oh_input_manager.h"
#include "oh_key_code.h"
#ifdef OHOS_BUILD_ENABLE_INFRARED_EMITTER
#include "infrared_emitter_controller.h"
#endif

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputNativeTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;

constexpr float DISPLAY_X { 100.0 };
constexpr float DISPLAY_Y { 200.0 };
constexpr double DEFAULT_AXIS_VALUE { 50.0 };
constexpr double AXIS_VALUE { 100.0 };
constexpr int64_t DEFAULT_ACTIONE_TIME { 10 };
constexpr int64_t ACTIONE_TIME { 20 };
} // namespace

class InputNativeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: InputNativeTest_KeyState_001
 * @tc.desc: Verify the create and destroy of key states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyState_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    if (keyState == nullptr) {
        ASSERT_EQ(keyState, nullptr);
    } else {
        ASSERT_NE(keyState, nullptr);
        OH_Input_DestroyKeyState(&keyState);
    }
}

/**
 * @tc.name: InputNativeTest_KeyCode_001
 * @tc.desc: Verify the set and get of key states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyCode_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeyCode(keyState, 2000);
    int32_t keyCode = OH_Input_GetKeyCode(keyState);
    ASSERT_EQ(keyCode, 2000);
    OH_Input_DestroyKeyState(&keyState);
}

/**
 * @tc.name: InputNativeTest_KeyPressed_001
 * @tc.desc: Verify the set and get of key pressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyPressed_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeyPressed(keyState, 0);
    int32_t keyAction = OH_Input_GetKeyPressed(keyState);
    ASSERT_EQ(keyAction, 0);
    OH_Input_DestroyKeyState(&keyState);
}

/**
 * @tc.name: InputNativeTest_KeySwitch_001
 * @tc.desc: Verify the set and get of key switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeySwitch_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeySwitch(keyState, 2);
    int32_t keySwitch = OH_Input_GetKeySwitch(keyState);
    ASSERT_EQ(keySwitch, 2);
    OH_Input_DestroyKeyState(&keyState);
}

/**
 * @tc.name: InputNativeTest_GetKeyState_001
 * @tc.desc: Verify the GetKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_GetKeyState_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeyCode(keyState, 22);
    OH_Input_GetKeyState(keyState);
    ASSERT_EQ(OH_Input_GetKeyPressed(keyState), KEY_RELEASED);
    ASSERT_EQ(OH_Input_GetKeySwitch(keyState), KEY_DEFAULT);
    ASSERT_EQ(OH_Input_GetKeyState(keyState), INPUT_SUCCESS);
    OH_Input_DestroyKeyState(&keyState);
}

/**
 * @tc.name: InputNativeTest_InjectKeyEvent_001
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectKeyEvent_001, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventAction(keyEvent, KEY_ACTION_DOWN);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_UNKNOWN);
    OH_Input_SetKeyEventActionTime(keyEvent, -1);
    int32_t retResult = OH_Input_InjectKeyEvent(keyEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetKeyEventAction(keyEvent, KEY_ACTION_UP);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_UNKNOWN);
    OH_Input_SetKeyEventActionTime(keyEvent, -1);
    retResult = OH_Input_InjectKeyEvent(keyEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    InputManager::GetInstance()->Authorize(true);
    OH_Input_CancelInjection();
    OH_Input_DestroyKeyEvent(&keyEvent);
    EXPECT_EQ(keyEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_KeyEventAction_001
 * @tc.desc: Verify the set and get of keyEvent action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyEventAction_001, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventAction(keyEvent, KEY_ACTION_DOWN);
    int32_t action = OH_Input_GetKeyEventAction(keyEvent);
    EXPECT_EQ(action, KEY_ACTION_DOWN);
    OH_Input_DestroyKeyEvent(&keyEvent);
    EXPECT_EQ(keyEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_KeyEventKeyCode_001
 * @tc.desc: Verify the set and get of keyEvent code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyEventKeyCode_001, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_A);
    int32_t keyCode = OH_Input_GetKeyEventKeyCode(keyEvent);
    EXPECT_EQ(keyCode, KEYCODE_A);
    OH_Input_DestroyKeyEvent(&keyEvent);
    EXPECT_EQ(keyEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_KeyEventActionTime_001
 * @tc.desc: Verify the set and get of keyEvent time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyEventActionTime_001, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventActionTime(keyEvent, 200);
    int64_t actionTime = OH_Input_GetKeyEventActionTime(keyEvent);
    EXPECT_EQ(actionTime, 200);
    OH_Input_DestroyKeyEvent(&keyEvent);
    EXPECT_EQ(keyEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_InjectMouseEvent_001
 * @tc.desc: Verify the InjectMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectMouseEvent_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_MOVE);
    OH_Input_SetMouseEventDisplayX(mouseEvent, 350);
    OH_Input_SetMouseEventDisplayY(mouseEvent, 350);
    OH_Input_SetMouseEventButton(mouseEvent, -2);
    OH_Input_SetMouseEventActionTime(mouseEvent, -1);
    int32_t retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_InjectMouseEvent_002
 * @tc.desc: Verify the InjectMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectMouseEvent_002, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_BEGIN);
    OH_Input_SetMouseEventDisplayX(mouseEvent, 350);
    OH_Input_SetMouseEventDisplayY(mouseEvent, 350);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_VERTICAL);
    OH_Input_SetMouseEventAxisValue(mouseEvent, 1.1);
    OH_Input_SetMouseEventButton(mouseEvent, -2);
    OH_Input_SetMouseEventActionTime(mouseEvent, -1);
    int32_t retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_END);
    OH_Input_SetMouseEventDisplayX(mouseEvent, 350);
    OH_Input_SetMouseEventDisplayY(mouseEvent, 350);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_VERTICAL);
    OH_Input_SetMouseEventAxisValue(mouseEvent, 1.1);
    OH_Input_SetMouseEventButton(mouseEvent, -2);
    OH_Input_SetMouseEventActionTime(mouseEvent, -1);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_MouseEventAction_001
 * @tc.desc: Verify the set and get of mouseEvent action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_MouseEventAction_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_BUTTON_DOWN);
    int32_t action = OH_Input_GetMouseEventAction(mouseEvent);
    EXPECT_EQ(action, MOUSE_ACTION_BUTTON_DOWN);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_MouseEventDisplayX_001
 * @tc.desc: Verify the set and get of mouseEvent displayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_MouseEventDisplayX_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventDisplayX(mouseEvent, 100);
    int32_t displayX = OH_Input_GetMouseEventDisplayX(mouseEvent);
    EXPECT_EQ(displayX, 100);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_MouseEventDisplayY_001
 * @tc.desc: Verify the set and get of mouseEvent displayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_MouseEventDisplayY_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventDisplayY(mouseEvent, 100);
    int32_t displayY = OH_Input_GetMouseEventDisplayY(mouseEvent);
    EXPECT_EQ(displayY, 100);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_MouseEventButton_001
 * @tc.desc: Verify the set and get of mouseEvent button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_MouseEventButton_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_LEFT);
    int32_t button = OH_Input_GetMouseEventButton(mouseEvent);
    EXPECT_EQ(button, MOUSE_BUTTON_LEFT);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_MouseEventAxisType_001
 * @tc.desc: Verify the set and get of mouseEvent axisType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_MouseEventAxisType_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_VERTICAL);
    int32_t axisType = OH_Input_GetMouseEventAxisType(mouseEvent);
    EXPECT_EQ(axisType, MOUSE_BUTTON_LEFT);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_MouseEventAxisValue_001
 * @tc.desc: Verify the set and get of mouseEvent axisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_MouseEventAxisValue_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventAxisValue(mouseEvent, 15.0);
    float axisValue = OH_Input_GetMouseEventAxisValue(mouseEvent);
    EXPECT_EQ(axisValue, 15.0);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_MouseEventActionTime_001
 * @tc.desc: Verify the set and get of mouseEvent actionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_MouseEventActionTime_001, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventActionTime(mouseEvent, 200);
    int64_t actionTime = OH_Input_GetMouseEventActionTime(mouseEvent);
    EXPECT_EQ(actionTime, 200);
    OH_Input_DestroyMouseEvent(&mouseEvent);
    EXPECT_EQ(mouseEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_InjectTouchEvent_001
 * @tc.desc: Verify the InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectTouchEvent_001, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_DOWN);
    OH_Input_SetTouchEventFingerId(touchEvent, 0);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, -10);
    OH_Input_SetTouchEventActionTime(touchEvent, -1);
    int32_t retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_UP);
    OH_Input_SetTouchEventFingerId(touchEvent, 0);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, -10);
    OH_Input_SetTouchEventActionTime(touchEvent, -1);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyTouchEvent(&touchEvent);
    EXPECT_EQ(touchEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_TouchEventAction_001
 * @tc.desc: Verify the set and get of touchEvent action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_TouchEventAction_001, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_DOWN);
    int32_t action = OH_Input_GetTouchEventAction(touchEvent);
    EXPECT_EQ(action, TOUCH_ACTION_DOWN);
    OH_Input_DestroyTouchEvent(&touchEvent);
    EXPECT_EQ(touchEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_TouchEventFingerId_001
 * @tc.desc: Verify the set and get of touchEvent id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_TouchEventFingerId_001, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventFingerId(touchEvent, 0);
    int32_t id = OH_Input_GetTouchEventFingerId(touchEvent);
    EXPECT_EQ(id, 0);
    OH_Input_DestroyTouchEvent(&touchEvent);
    EXPECT_EQ(touchEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_TouchEventDisplayX_001
 * @tc.desc: Verify the set and get of touchEvent displayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_TouchEventDisplayX_001, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventDisplayX(touchEvent, 100);
    int32_t displayX = OH_Input_GetTouchEventDisplayX(touchEvent);
    EXPECT_EQ(displayX, 100);
    OH_Input_DestroyTouchEvent(&touchEvent);
    EXPECT_EQ(touchEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_TouchEventDisplayY_001
 * @tc.desc: Verify the set and get of touchEvent displayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_TouchEventDisplayY_001, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventDisplayY(touchEvent, 100);
    int32_t displayY = OH_Input_GetTouchEventDisplayY(touchEvent);
    EXPECT_EQ(displayY, 100);
    OH_Input_DestroyTouchEvent(&touchEvent);
    EXPECT_EQ(touchEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_TouchEventActionTime_001
 * @tc.desc: Verify the set and get of touchEvent actionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_TouchEventActionTime_001, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventActionTime(touchEvent, 200);
    int64_t actionTime = OH_Input_GetTouchEventActionTime(touchEvent);
    EXPECT_EQ(actionTime, 200);
    OH_Input_DestroyTouchEvent(&touchEvent);
    EXPECT_EQ(touchEvent, nullptr);
}

/**
 * @tc.name: InputNativeTest_InjectKeyEvent_002
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectKeyEvent_002, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_VOLUME_DOWN);
    std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
    g_keyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
    int32_t retResult = OH_Input_InjectKeyEvent(keyEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectKeyEvent_003
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectKeyEvent_003, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_VOLUME_DOWN);
    std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
    g_keyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OH_Input_SetKeyEventActionTime(keyEvent, -1);
    int32_t retResult = OH_Input_InjectKeyEvent(keyEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectKeyEvent_004
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectKeyEvent_004, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_VOLUME_DOWN);
    std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
    g_keyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OH_Input_SetKeyEventActionTime(keyEvent, 2);
    OH_Input_SetKeyEventAction(keyEvent, KEY_ACTION_DOWN);
    int32_t retResult = OH_Input_InjectKeyEvent(keyEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectKeyEvent_005
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectKeyEvent_005, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_VOLUME_DOWN);
    std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
    g_keyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OH_Input_SetKeyEventActionTime(keyEvent, 2);
    OH_Input_SetKeyEventAction(keyEvent, KEY_ACTION_UP);
    int32_t retResult = OH_Input_InjectKeyEvent(keyEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectKeyEvent_006
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectKeyEvent_006, TestSize.Level1)
{
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    OH_Input_SetKeyEventKeyCode(keyEvent, KEYCODE_VOLUME_DOWN);
    std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
    g_keyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OH_Input_SetKeyEventActionTime(keyEvent, 2);
    OH_Input_SetKeyEventAction(keyEvent, KeyEvent::KEY_ACTION_UNKNOWN);
    int32_t retResult = OH_Input_InjectKeyEvent(keyEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectMouseEvent_003
 * @tc.desc: Verify the InjectMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectMouseEvent_003, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_BEGIN);
    OH_Input_SetMouseEventDisplayX(mouseEvent, 350);
    OH_Input_SetMouseEventDisplayY(mouseEvent, 350);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_VERTICAL);
    OH_Input_SetMouseEventAxisValue(mouseEvent, 1.1);
    OH_Input_SetMouseEventButton(mouseEvent, 3);
    OH_Input_SetMouseEventActionTime(mouseEvent, -1);
    int32_t retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectTouchEvent_002
 * @tc.desc: Verify the InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectTouchEvent_002, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_UP);
    OH_Input_SetTouchEventFingerId(touchEvent, 0);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, 10);
    OH_Input_SetTouchEventActionTime(touchEvent, -1);
    int32_t retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_InjectTouchEvent_003
 * @tc.desc: Verify the InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectTouchEvent_003, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_DOWN);
    OH_Input_SetTouchEventFingerId(touchEvent, 0);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, 10);
    OH_Input_SetTouchEventActionTime(touchEvent, -1);
    int32_t retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectMouseEvent_004
 * @tc.desc: Verify the InjectMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectMouseEvent_004, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_CANCEL);
    OH_Input_SetMouseEventDisplayX(mouseEvent, 350);
    OH_Input_SetMouseEventDisplayY(mouseEvent, 350);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_VERTICAL);
    OH_Input_SetMouseEventAxisValue(mouseEvent, 1.1);
    OH_Input_SetMouseEventActionTime(mouseEvent, 2);
    int32_t retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_MOVE);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_NONE);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_BUTTON_DOWN);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_LEFT);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_BUTTON_UP);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_MIDDLE);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_BEGIN);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_RIGHT);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_UPDATE);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_FORWARD);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectMouseEvent_005
 * @tc.desc: Verify the InjectMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectMouseEvent_005, TestSize.Level1)
{
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    ASSERT_NE(mouseEvent, nullptr);
    OH_Input_SetMouseEventDisplayX(mouseEvent, 350);
    OH_Input_SetMouseEventDisplayY(mouseEvent, 350);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_VERTICAL);
    OH_Input_SetMouseEventAxisValue(mouseEvent, 1.1);
    OH_Input_SetMouseEventActionTime(mouseEvent, 2);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_END);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_BACK);
    int32_t retResult = OH_Input_InjectMouseEvent(mouseEvent);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_END);
    OH_Input_SetMouseEventButton(mouseEvent, 7);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetMouseEventAction(mouseEvent, 10);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_HORIZONTAL);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_BEGIN);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_BACK);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetMouseEventAxisType(mouseEvent, 5);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_BEGIN);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_BACK);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetMouseEventAxisType(mouseEvent, MOUSE_AXIS_SCROLL_VERTICAL);
    OH_Input_SetMouseEventAction(mouseEvent, MOUSE_ACTION_AXIS_BEGIN);
    OH_Input_SetMouseEventButton(mouseEvent, MOUSE_BUTTON_BACK);
    retResult = OH_Input_InjectMouseEvent(mouseEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_InjectTouchEvent_004
 * @tc.desc: Verify the InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectTouchEvent_004, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(g_keyEvent, nullptr);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_CANCEL);
    OH_Input_SetTouchEventFingerId(touchEvent, 0);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, 10);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    int32_t retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_DOWN);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_MOVE);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_UP);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, 10);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_InjectTouchEvent_005
 * @tc.desc: Verify the InjectTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_InjectTouchEvent_005, TestSize.Level1)
{
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(g_keyEvent, nullptr);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_CANCEL);
    OH_Input_SetTouchEventFingerId(touchEvent, 0);
    OH_Input_SetTouchEventDisplayX(touchEvent, -10);
    OH_Input_SetTouchEventDisplayY(touchEvent, 10);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_DOWN);
    int32_t retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, 10);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_DOWN);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, 10);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_MOVE);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    OH_Input_SetTouchEventDisplayX(touchEvent, 671);
    OH_Input_SetTouchEventDisplayY(touchEvent, 10);
    OH_Input_SetTouchEventActionTime(touchEvent, 2);
    OH_Input_SetTouchEventAction(touchEvent, TOUCH_ACTION_CANCEL);
    retResult = OH_Input_InjectTouchEvent(touchEvent);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_CreateAxisEvent_001
 * @tc.desc: Verify the OH_Input_CreateAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_CreateAxisEvent_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);

    InputEvent_AxisAction action = AXIS_ACTION_BEGIN;
    Input_Result result = OH_Input_SetAxisEventAction(axisEvent, action);
    EXPECT_EQ(result, INPUT_SUCCESS);
    action = AXIS_ACTION_UPDATE;
    result = OH_Input_GetAxisEventAction(axisEvent, &action);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_EQ(action, AXIS_ACTION_BEGIN);

    float displayX = DISPLAY_X;
    result = OH_Input_SetAxisEventDisplayX(axisEvent, displayX);
    EXPECT_EQ(result, INPUT_SUCCESS);
    displayX = DISPLAY_Y;
    result = OH_Input_GetAxisEventDisplayX(axisEvent, &displayX);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_FLOAT_EQ(displayX, DISPLAY_X);

    float displayY = DISPLAY_Y;
    result = OH_Input_SetAxisEventDisplayY(axisEvent, displayY);
    EXPECT_EQ(result, INPUT_SUCCESS);
    displayY = DISPLAY_X;
    result = OH_Input_GetAxisEventDisplayY(axisEvent, &displayY);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_FLOAT_EQ(displayY, DISPLAY_Y);

    InputEvent_AxisType axisType = AXIS_TYPE_SCROLL_VERTICAL;
    double axisValue = DEFAULT_AXIS_VALUE;
    result = OH_Input_SetAxisEventAxisValue(axisEvent, axisType, axisValue);
    EXPECT_EQ(result, INPUT_SUCCESS);
    axisValue = AXIS_VALUE;
    result = OH_Input_GetAxisEventAxisValue(axisEvent, axisType, &axisValue);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_DOUBLE_EQ(axisValue, DEFAULT_AXIS_VALUE);

    int64_t actionTime = DEFAULT_ACTIONE_TIME;
    result = OH_Input_SetAxisEventActionTime(axisEvent, actionTime);
    EXPECT_EQ(result, INPUT_SUCCESS);
    actionTime = ACTIONE_TIME;
    result = OH_Input_GetAxisEventActionTime(axisEvent, &actionTime);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_EQ(actionTime, DEFAULT_ACTIONE_TIME);

    InputEvent_AxisEventType axisEventType = AXIS_EVENT_TYPE_PINCH;
    result = OH_Input_SetAxisEventType(axisEvent, axisEventType);
    EXPECT_EQ(result, INPUT_SUCCESS);
    axisEventType = AXIS_EVENT_TYPE_SCROLL;
    result = OH_Input_GetAxisEventType(axisEvent, &axisEventType);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_EQ(axisEventType, AXIS_EVENT_TYPE_PINCH);

    InputEvent_SourceType sourceType = SOURCE_TYPE_MOUSE;
    result = OH_Input_SetAxisEventSourceType(axisEvent, sourceType);
    EXPECT_EQ(result, INPUT_SUCCESS);
    sourceType = SOURCE_TYPE_TOUCHSCREEN;
    result = OH_Input_GetAxisEventSourceType(axisEvent, &sourceType);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_EQ(sourceType, SOURCE_TYPE_MOUSE);

    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_DestroyAxisEvent_001
 * @tc.desc: Verify the OH_Input_DestroyAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_DestroyAxisEvent_001, TestSize.Level1)
{
    Input_Result result = OH_Input_DestroyAxisEvent(nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_SetAxisEventAction_001
 * @tc.desc: Verify the OH_Input_SetAxisEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_SetAxisEventAction_001, TestSize.Level1)
{
    InputEvent_AxisAction action = AXIS_ACTION_BEGIN;
    Input_Result result = OH_Input_SetAxisEventAction(nullptr, action);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventAction_001
 * @tc.desc: Verify the OH_Input_GetAxisEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventAction_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    Input_Result result = OH_Input_GetAxisEventAction(axisEvent, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventAction_002
 * @tc.desc: Verify the OH_Input_GetAxisEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventAction_002, TestSize.Level1)
{
    InputEvent_AxisAction action = AXIS_ACTION_END;
    Input_Result result = OH_Input_GetAxisEventAction(nullptr, &action);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventAction_003
 * @tc.desc: Verify the OH_Input_GetAxisEventAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventAction_003, TestSize.Level1)
{
    Input_Result result = OH_Input_GetAxisEventAction(nullptr, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_SetAxisEventDisplayX_001
 * @tc.desc: Verify the OH_Input_SetAxisEventDisplayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_SetAxisEventDisplayX_001, TestSize.Level1)
{
    float displayX = DISPLAY_X;
    Input_Result result = OH_Input_SetAxisEventDisplayX(nullptr, displayX);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventDisplayX_001
 * @tc.desc: Verify the OH_Input_GetAxisEventDisplayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventDisplayX_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    Input_Result result = OH_Input_GetAxisEventDisplayX(axisEvent, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventDisplayX_002
 * @tc.desc: Verify the OH_Input_GetAxisEventDisplayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventDisplayX_002, TestSize.Level1)
{
    float displayX = DISPLAY_X;
    Input_Result result = OH_Input_GetAxisEventDisplayX(nullptr, &displayX);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventDisplayX_003
 * @tc.desc: Verify the OH_Input_GetAxisEventDisplayX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventDisplayX_003, TestSize.Level1)
{
    Input_Result result = OH_Input_GetAxisEventDisplayX(nullptr, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_SetAxisEventDisplayY_001
 * @tc.desc: Verify the OH_Input_SetAxisEventDisplayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_SetAxisEventDisplayY_001, TestSize.Level1)
{
    float displayY = DISPLAY_Y;
    Input_Result result = OH_Input_SetAxisEventDisplayY(nullptr, displayY);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventDisplayY_001
 * @tc.desc: Verify the OH_Input_GetAxisEventDisplayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventDisplayY_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    Input_Result result = OH_Input_GetAxisEventDisplayY(axisEvent, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventDisplayY_002
 * @tc.desc: Verify the OH_Input_GetAxisEventDisplayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventDisplayY_002, TestSize.Level1)
{
    float displayY = DISPLAY_Y;
    Input_Result result = OH_Input_GetAxisEventDisplayY(nullptr, &displayY);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventDisplayY_003
 * @tc.desc: Verify the OH_Input_GetAxisEventDisplayY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventDisplayY_003, TestSize.Level1)
{
    Input_Result result = OH_Input_GetAxisEventDisplayY(nullptr, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_SetAxisEventAxisValue_001
 * @tc.desc: Verify the OH_Input_SetAxisEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_SetAxisEventAxisValue_001, TestSize.Level1)
{
    InputEvent_AxisType axisType = AXIS_TYPE_SCROLL_VERTICAL;
    double axisValue = DEFAULT_AXIS_VALUE;
    Input_Result result = OH_Input_SetAxisEventAxisValue(nullptr, axisType, axisValue);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventAxisValue_001
 * @tc.desc: Verify the OH_Input_GetAxisEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventAxisValue_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    InputEvent_AxisType axisType = AXIS_TYPE_SCROLL_VERTICAL;
    Input_Result result = OH_Input_GetAxisEventAxisValue(axisEvent, axisType, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventAxisValue_002
 * @tc.desc: Verify the OH_Input_GetAxisEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventAxisValue_002, TestSize.Level1)
{
    InputEvent_AxisType axisType = AXIS_TYPE_SCROLL_VERTICAL;
    double axisValue = DEFAULT_AXIS_VALUE;
    Input_Result result = OH_Input_GetAxisEventAxisValue(nullptr, axisType, &axisValue);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventAxisValue_003
 * @tc.desc: Verify the OH_Input_GetAxisEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventAxisValue_003, TestSize.Level1)
{
    InputEvent_AxisType axisType = AXIS_TYPE_SCROLL_VERTICAL;
    Input_Result result = OH_Input_GetAxisEventAxisValue(nullptr, axisType, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventAxisValue_004
 * @tc.desc: Verify the OH_Input_GetAxisEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventAxisValue_004, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    InputEvent_AxisType axisType = AXIS_TYPE_SCROLL_VERTICAL;
    double axisValue = DEFAULT_AXIS_VALUE;
    Input_Result result = OH_Input_GetAxisEventAxisValue(axisEvent, axisType, &axisValue);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_SetAxisEventActionTime_001
 * @tc.desc: Verify the OH_Input_SetAxisEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_SetAxisEventActionTime_001, TestSize.Level1)
{
    int64_t actionTime = DEFAULT_ACTIONE_TIME;
    Input_Result result = OH_Input_SetAxisEventActionTime(nullptr, actionTime);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventActionTime_001
 * @tc.desc: Verify the OH_Input_GetAxisEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventActionTime_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    Input_Result result = OH_Input_GetAxisEventActionTime(axisEvent, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventActionTime_002
 * @tc.desc: Verify the OH_Input_GetAxisEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventActionTime_002, TestSize.Level1)
{
    int64_t actionTime = DEFAULT_ACTIONE_TIME;
    Input_Result result = OH_Input_GetAxisEventActionTime(nullptr, &actionTime);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventActionTime_003
 * @tc.desc: Verify the OH_Input_GetAxisEventActionTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventActionTime_003, TestSize.Level1)
{
    Input_Result result = OH_Input_GetAxisEventActionTime(nullptr, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_SetAxisEventType_001
 * @tc.desc: Verify the OH_Input_SetAxisEventType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_SetAxisEventType_001, TestSize.Level1)
{
    InputEvent_AxisEventType axisEventType = AXIS_EVENT_TYPE_PINCH;
    Input_Result result = OH_Input_SetAxisEventType(nullptr, axisEventType);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventType_001
 * @tc.desc: Verify the OH_Input_GetAxisEventType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventType_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    Input_Result result = OH_Input_GetAxisEventType(axisEvent, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventType_002
 * @tc.desc: Verify the OH_Input_GetAxisEventType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventType_002, TestSize.Level1)
{
    InputEvent_AxisEventType axisEventType = AXIS_EVENT_TYPE_PINCH;
    Input_Result result = OH_Input_GetAxisEventType(nullptr, &axisEventType);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventType_003
 * @tc.desc: Verify the OH_Input_GetAxisEventType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventType_003, TestSize.Level1)
{
    Input_Result result = OH_Input_GetAxisEventType(nullptr, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_SetAxisEventSourceType_001
 * @tc.desc: Verify the OH_Input_SetAxisEventSourceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_SetAxisEventSourceType_001, TestSize.Level1)
{
    InputEvent_SourceType sourceType = SOURCE_TYPE_MOUSE;
    Input_Result result = OH_Input_SetAxisEventSourceType(nullptr, sourceType);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventSourceType_001
 * @tc.desc: Verify the OH_Input_GetAxisEventSourceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventSourceType_001, TestSize.Level1)
{
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    EXPECT_NE(axisEvent, nullptr);
    Input_Result result = OH_Input_GetAxisEventSourceType(axisEvent, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
    result = OH_Input_DestroyAxisEvent(&axisEvent);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventSourceType_002
 * @tc.desc: Verify the OH_Input_GetAxisEventSourceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventSourceType_002, TestSize.Level1)
{
    InputEvent_SourceType sourceType = SOURCE_TYPE_MOUSE;
    Input_Result result = OH_Input_GetAxisEventSourceType(nullptr, &sourceType);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_GetAxisEventSourceType_003
 * @tc.desc: Verify the OH_Input_GetAxisEventSourceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_GetAxisEventSourceType_003, TestSize.Level1)
{
    Input_Result result = OH_Input_GetAxisEventSourceType(nullptr, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

static void KeyEventCallback(const struct Input_KeyEvent* keyEvent)
{
    EXPECT_NE(keyEvent, nullptr);
    int32_t action = OH_Input_GetKeyEventAction(keyEvent);
    int32_t keyCode = OH_Input_GetKeyEventKeyCode(keyEvent);
    MMI_HILOGI("KeyEventCallback, action:%{public}d, keyCode:%{public}d,", action, keyCode);
}

static void MouseEventCallback(const struct Input_MouseEvent* mouseEvent)
{
    EXPECT_NE(mouseEvent, nullptr);
    int32_t action = OH_Input_GetMouseEventAction(mouseEvent);
    int32_t displayX = OH_Input_GetMouseEventDisplayX(mouseEvent);
    int32_t displayY = OH_Input_GetMouseEventDisplayY(mouseEvent);
    MMI_HILOGI("MouseEventCallback, action:%{public}d, displayX:%{public}d, displayY:%{public}d",
        action, displayX, displayY);
}

static void TouchEventCallback(const struct Input_TouchEvent* touchEvent)
{
    EXPECT_NE(touchEvent, nullptr);
    int32_t action = OH_Input_GetTouchEventAction(touchEvent);
    int32_t id = OH_Input_GetTouchEventFingerId(touchEvent);
    MMI_HILOGI("TouchEventCallback, action:%{public}d, id:%{public}d", action, id);
}

static void AxisEventCallbackAll(const struct Input_AxisEvent* axisEvent)
{
    EXPECT_NE(axisEvent, nullptr);
    InputEvent_AxisAction axisAction = AXIS_ACTION_BEGIN;
    OH_Input_GetAxisEventAction(axisEvent, &axisAction);
    InputEvent_AxisEventType sourceType = AXIS_EVENT_TYPE_PINCH;
    OH_Input_GetAxisEventType(axisEvent, &sourceType);
    InputEvent_SourceType axisEventType = SOURCE_TYPE_MOUSE;
    OH_Input_GetAxisEventSourceType(axisEvent, &axisEventType);
    MMI_HILOGI("AxisEventCallbackAll, axisAction:%{public}d, sourceType:%{public}d, axisEventType:%{public}d",
        axisAction, sourceType, axisEventType);
}

static void AxisEventCallback(const struct Input_AxisEvent* axisEvent)
{
    EXPECT_NE(axisEvent, nullptr);
    InputEvent_AxisAction axisAction = AXIS_ACTION_BEGIN;
    OH_Input_GetAxisEventAction(axisEvent, &axisAction);
    InputEvent_AxisEventType sourceType = AXIS_EVENT_TYPE_PINCH;
    OH_Input_GetAxisEventType(axisEvent, &sourceType);
    InputEvent_SourceType axisEventType = SOURCE_TYPE_MOUSE;
    OH_Input_GetAxisEventSourceType(axisEvent, &axisEventType);
    MMI_HILOGI("AxisEventCallback, axisAction:%{public}d, sourceType:%{public}d, axisEventType:%{public}d",
        axisAction, sourceType, axisEventType);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddKeyEventMonitor_001
 * @tc.desc: Verify the OH_Input_AddKeyEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddKeyEventMonitor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddKeyEventMonitor(KeyEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveKeyEventMonitor(KeyEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddKeyEventMonitor_002
 * @tc.desc: Verify the OH_Input_AddKeyEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddKeyEventMonitor_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddKeyEventMonitor(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveKeyEventMonitor_001
 * @tc.desc: Verify the OH_Input_RemoveKeyEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveKeyEventMonitor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveKeyEventMonitor(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveKeyEventMonitor_002
 * @tc.desc: Verify the OH_Input_RemoveKeyEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveKeyEventMonitor_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveKeyEventMonitor(KeyEventCallback);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    retResult = OH_Input_AddKeyEventMonitor(KeyEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveKeyEventMonitor(KeyEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}


/**
 * @tc.name: InputNativeTest_OH_Input_AddMouseEventMonitor_001
 * @tc.desc: Verify the OH_Input_AddMouseEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddMouseEventMonitor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddMouseEventMonitor(MouseEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveMouseEventMonitor(MouseEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddMouseEventMonitor_002
 * @tc.desc: Verify the OH_Input_AddMouseEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddMouseEventMonitor_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddMouseEventMonitor(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveMouseEventMonitor_001
 * @tc.desc: Verify the OH_Input_RemoveMouseEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveMouseEventMonitor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveMouseEventMonitor(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveMouseEventMonitor_002
 * @tc.desc: Verify the OH_Input_RemoveMouseEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveMouseEventMonitor_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveMouseEventMonitor(MouseEventCallback);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    retResult = OH_Input_AddMouseEventMonitor(MouseEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveMouseEventMonitor(MouseEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddTouchEventMonitor_001
 * @tc.desc: Verify the OH_Input_AddTouchEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddTouchEventMonitor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddTouchEventMonitor(TouchEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveTouchEventMonitor(TouchEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddTouchEventMonitor_002
 * @tc.desc: Verify the OH_Input_AddTouchEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddTouchEventMonitor_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddTouchEventMonitor(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveTouchEventMonitor_001
 * @tc.desc: Verify the OH_Input_RemoveTouchEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveTouchEventMonitor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveTouchEventMonitor(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveTouchEventMonitor_002
 * @tc.desc: Verify the OH_Input_RemoveTouchEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveTouchEventMonitor_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveTouchEventMonitor(TouchEventCallback);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    retResult = OH_Input_AddTouchEventMonitor(TouchEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveTouchEventMonitor(TouchEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}


/**
 * @tc.name: InputNativeTest_OH_Input_AddAxisEventMonitorForAll_001
 * @tc.desc: Verify the OH_Input_AddAxisEventMonitorForAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddAxisEventMonitorForAll_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddAxisEventMonitorForAll(AxisEventCallbackAll);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveAxisEventMonitorForAll(AxisEventCallbackAll);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddAxisEventMonitorForAll_002
 * @tc.desc: Verify the OH_Input_AddAxisEventMonitorForAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddAxisEventMonitorForAll_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddAxisEventMonitorForAll(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveAxisEventMonitorForAll_001
 * @tc.desc: Verify the OH_Input_RemoveAxisEventMonitorForAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveAxisEventMonitorForAll_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveAxisEventMonitorForAll(nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveAxisEventMonitorForAll_002
 * @tc.desc: Verify the OH_Input_RemoveAxisEventMonitorForAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveAxisEventMonitorForAll_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveAxisEventMonitorForAll(AxisEventCallbackAll);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    retResult = OH_Input_AddAxisEventMonitorForAll(AxisEventCallbackAll);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveAxisEventMonitorForAll(AxisEventCallbackAll);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddAxisEventMonitor_001
 * @tc.desc: Verify the OH_Input_AddAxisEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddAxisEventMonitor_001, TestSize.Level1)
{
    InputEvent_AxisEventType axisEventType = AXIS_EVENT_TYPE_PINCH;
    Input_Result retResult = OH_Input_AddAxisEventMonitor(axisEventType, AxisEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveAxisEventMonitor(axisEventType, AxisEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddAxisEventMonitor_002
 * @tc.desc: Verify the OH_Input_AddAxisEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddAxisEventMonitor_002, TestSize.Level1)
{
    InputEvent_AxisEventType axisEventType = AXIS_EVENT_TYPE_PINCH;
    Input_Result retResult = OH_Input_AddAxisEventMonitor(axisEventType, nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveAxisEventMonitor_001
 * @tc.desc: Verify the OH_Input_RemoveAxisEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveAxisEventMonitor_001, TestSize.Level1)
{
    InputEvent_AxisEventType axisEventType = AXIS_EVENT_TYPE_PINCH;
    Input_Result retResult = OH_Input_RemoveAxisEventMonitor(axisEventType, nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveAxisEventMonitor_002
 * @tc.desc: Verify the OH_Input_RemoveAxisEventMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveAxisEventMonitor_002, TestSize.Level1)
{
    InputEvent_AxisEventType axisEventType = AXIS_EVENT_TYPE_PINCH;
    Input_Result retResult = OH_Input_RemoveAxisEventMonitor(axisEventType, AxisEventCallback);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    retResult = OH_Input_AddAxisEventMonitor(axisEventType, AxisEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveAxisEventMonitor(AXIS_EVENT_TYPE_SCROLL, AxisEventCallback);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
    retResult = OH_Input_RemoveAxisEventMonitor(axisEventType, AxisEventCallback);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddKeyEventInterceptor_001
 * @tc.desc: Verify the OH_Input_AddKeyEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddKeyEventInterceptor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddKeyEventInterceptor(nullptr, nullptr);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddKeyEventInterceptor_002
 * @tc.desc: Verify the OH_Input_AddKeyEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddKeyEventInterceptor_002, TestSize.Level1)
{
    Input_Result retResult = OH_Input_AddKeyEventInterceptor(KeyEventCallback, nullptr);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_AddKeyEventInterceptor(KeyEventCallback, nullptr);
    EXPECT_EQ(retResult, INPUT_REPEAT_INTERCEPTOR);
    retResult = OH_Input_RemoveKeyEventInterceptor();
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveKeyEventInterceptor_001
 * @tc.desc: Verify the OH_Input_RemoveKeyEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveKeyEventInterceptor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveKeyEventInterceptor();
    EXPECT_EQ(retResult, INPUT_SERVICE_EXCEPTION);
    retResult = OH_Input_AddKeyEventInterceptor(KeyEventCallback, nullptr);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveKeyEventInterceptor();
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddInputEventInterceptor_001
 * @tc.desc: Verify the OH_Input_AddInputEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddInputEventInterceptor_001, TestSize.Level1)
{
    Input_InterceptorOptions *option = nullptr;
    Input_Result retResult = OH_Input_AddInputEventInterceptor(nullptr, option);
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeTest_OH_Input_AddInputEventInterceptor_002
 * @tc.desc: Verify the OH_Input_AddInputEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_AddInputEventInterceptor_002, TestSize.Level1)
{
    Input_InterceptorEventCallback callback;
    callback.mouseCallback = MouseEventCallback;
    callback.touchCallback = TouchEventCallback;
    callback.axisCallback = AxisEventCallback;
    Input_InterceptorOptions *option = nullptr;
    Input_Result retResult = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(retResult, INPUT_REPEAT_INTERCEPTOR);
    retResult = OH_Input_RemoveInputEventInterceptor();
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}

/**
 * @tc.name: InputNativeTest_OH_Input_RemoveInputEventInterceptor_001
 * @tc.desc: Verify the OH_Input_RemoveInputEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_OH_Input_RemoveInputEventInterceptor_001, TestSize.Level1)
{
    Input_Result retResult = OH_Input_RemoveInputEventInterceptor();
    EXPECT_EQ(retResult, INPUT_SERVICE_EXCEPTION);
    Input_InterceptorEventCallback callback;
    callback.mouseCallback = MouseEventCallback;
    callback.touchCallback = TouchEventCallback;
    callback.axisCallback = AxisEventCallback;
    Input_InterceptorOptions *option = nullptr;
    retResult = OH_Input_AddInputEventInterceptor(&callback, option);
    EXPECT_EQ(retResult, INPUT_SUCCESS);
    retResult = OH_Input_RemoveInputEventInterceptor();
    EXPECT_EQ(retResult, INPUT_SUCCESS);
}
} // namespace MMI
} // namespace OHOS
