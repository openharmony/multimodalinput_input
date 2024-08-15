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

#include "oh_input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputManagerTest"

struct Input_KeyState {
    int32_t keyCode;
    int32_t keyState;
    int32_t keySwitch;
};

struct Input_KeyEvent {
    int32_t action;
    int32_t keyCode;
    int64_t actionTime { -1 };
};

struct Input_MouseEvent {
    int32_t action;
    int32_t displayX;
    int32_t displayY;
    int32_t button { -1 };
    int32_t axisType { -1 };
    float axisValue { 0.0f };
    int64_t actionTime { -1 };
};

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class OHInputManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

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
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetKeyState_001, TestSize.Level1)
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
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectMouseEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_MouseEvent inputMouseEvent;
    inputMouseEvent.actionTime = -1;
    inputMouseEvent.action = MOUSE_ACTION_CANCEL;
    inputMouseEvent.axisType = MOUSE_AXIS_SCROLL_VERTICAL;
    inputMouseEvent.button = MOUSE_BUTTON_NONE;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS); // 1-8

    inputMouseEvent.actionTime = 100;
    inputMouseEvent.action = MOUSE_ACTION_MOVE;
    inputMouseEvent.axisType = MOUSE_AXIS_SCROLL_HORIZONTAL;
    inputMouseEvent.button = MOUSE_BUTTON_LEFT;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS); // 9-12

    inputMouseEvent.action = MOUSE_ACTION_BUTTON_DOWN;
    inputMouseEvent.button = MOUSE_BUTTON_MIDDLE;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS); // 13-15

    inputMouseEvent.action = MOUSE_ACTION_BUTTON_UP;
    inputMouseEvent.button = MOUSE_BUTTON_RIGHT;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS); // 16-18

    inputMouseEvent.action = MOUSE_ACTION_AXIS_BEGIN;
    inputMouseEvent.button = MOUSE_BUTTON_FORWARD;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS); // 19-20

    inputMouseEvent.action = MOUSE_ACTION_AXIS_UPDATE;
    inputMouseEvent.button = MOUSE_BUTTON_BACK;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS); // 21-22

    inputMouseEvent.action = MOUSE_ACTION_AXIS_END;
    inputMouseEvent.button = static_cast<Input_MouseEventButton>(10);
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PARAMETER_ERROR); // 23-24

    inputMouseEvent.action = static_cast<Input_MouseEventAction>(10);
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PARAMETER_ERROR); // 25
}
} // namespace MMI
} // namespace OHOS