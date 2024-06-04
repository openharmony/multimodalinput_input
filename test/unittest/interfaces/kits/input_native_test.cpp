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
#include "oh_input_manager.h"
#include "oh_key_code.h"
#ifdef OHOS_BUILD_ENABLE_INFRARED_EMITTER
#include "infrared_emitter_controller.h"
#endif
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
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
    EXPECT_EQ(retResult, INPUT_SUCCESS);
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
    EXPECT_EQ(retResult, INPUT_PARAMETER_ERROR);
}
} // namespace MMI
} // namespace OHOS
