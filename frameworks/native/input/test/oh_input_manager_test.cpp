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

struct Input_TouchEvent {
    int32_t action;
    int32_t id;
    int32_t displayX;
    int32_t displayY;
    int64_t actionTime { -1 };
};

struct Input_AxisEvent {
    int32_t axisAction;
    float displayX;
    float displayY;
    std::map<int32_t, double> axisValues;
    int64_t actionTime { -1 };
    int32_t sourceType;
    int32_t axisEventType { -1 };
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
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS);

    inputMouseEvent.actionTime = 100;
    inputMouseEvent.action = MOUSE_ACTION_MOVE;
    inputMouseEvent.axisType = MOUSE_AXIS_SCROLL_HORIZONTAL;
    inputMouseEvent.button = MOUSE_BUTTON_LEFT;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS);

    inputMouseEvent.action = MOUSE_ACTION_BUTTON_DOWN;
    inputMouseEvent.button = MOUSE_BUTTON_MIDDLE;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS);

    inputMouseEvent.action = MOUSE_ACTION_BUTTON_UP;
    inputMouseEvent.button = MOUSE_BUTTON_RIGHT;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS);

    inputMouseEvent.action = MOUSE_ACTION_AXIS_BEGIN;
    inputMouseEvent.button = MOUSE_BUTTON_FORWARD;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS);

    inputMouseEvent.action = MOUSE_ACTION_AXIS_UPDATE;
    inputMouseEvent.button = MOUSE_BUTTON_BACK;
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_SUCCESS);

    inputMouseEvent.action = MOUSE_ACTION_AXIS_END;
    inputMouseEvent.button = static_cast<Input_MouseEventButton>(10);
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PARAMETER_ERROR);

    inputMouseEvent.action = static_cast<Input_MouseEventAction>(10);
    EXPECT_EQ(OH_Input_InjectMouseEvent(&inputMouseEvent), INPUT_PARAMETER_ERROR);
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
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_InjectTouchEvent_001, TestSize.Level1)
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
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DestroyAxisEvent
 * @tc.desc: Test the funcation OH_Input_DestroyAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DestroyAxisEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_AxisEvent* inputAxisEvent = nullptr;
    EXPECT_EQ(OH_Input_DestroyAxisEvent(&inputAxisEvent), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_DestroyAxisEvent_001
 * @tc.desc: Test the funcation OH_Input_DestroyAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_DestroyAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_AxisEvent* inputAxisEvent = new (std::nothrow) Input_AxisEvent();
    EXPECT_EQ(OH_Input_DestroyAxisEvent(&inputAxisEvent), INPUT_SUCCESS);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_GetAxisEventAxisValue
 * @tc.desc: Test the funcation OH_Input_GetAxisEventAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetAxisEventAxisValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_AxisEvent inputAxisEvent;
    InputEvent_AxisType axisType = AXIS_TYPE_SCROLL_VERTICAL;
    double axisValue = 100.5;
    inputAxisEvent.axisValues.insert(std::make_pair(axisType, axisValue));
    EXPECT_EQ(OH_Input_GetAxisEventAxisValue(&inputAxisEvent, axisType, &axisValue), INPUT_SUCCESS);
    axisType = AXIS_TYPE_SCROLL_HORIZONTAL;
    EXPECT_EQ(OH_Input_GetAxisEventAxisValue(&inputAxisEvent, axisType, &axisValue), INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_SetKeyCode
 * @tc.desc: Test the funcation OH_Input_SetKeyCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_SetKeyCode, TestSize.Level1)
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
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_KeyCodeToString
 * @tc.desc: Test the funcation OH_Input_KeyCodeToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_KeyCodeToString, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str = OH_Input_KeyCodeToString(KEYCODE_F1);
    EXPECT_STREQ(str.c_str(), "KEYCODE_F1");
    str = OH_Input_KeyCodeToString(KEYCODE_F12);
    EXPECT_STREQ(str.c_str(), "KEYCODE_F12");
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_RegisterDeviceListener
 * @tc.desc: Test the funcation OH_Input_RegisterDeviceListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_RegisterDeviceListener, TestSize.Level1)
{
    auto listener1 = new (std::nothrow) Input_DeviceListener();
    if (listener1 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
        return;
    }
    listener1->OnDeviceAdded = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceAdded1: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    listener1->OnDeviceRemoved = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceRemoved1: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener1), INPUT_SUCCESS);

    auto listener2 = new (std::nothrow) Input_DeviceListener();
    if (listener2 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
        return;
    }
    listener2->OnDeviceAdded = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceAdded2: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    listener2->OnDeviceRemoved = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceRemoved2: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener2), INPUT_SUCCESS);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(listener1), INPUT_SUCCESS);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(listener2), INPUT_SUCCESS);
    delete listener1;
    delete listener2;
}

/**
 * @tc.name: OHInputManagerTest_OH_Input_UnregisterDeviceListener
 * @tc.desc: Test the funcation OH_Input_UnregisterDeviceListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_UnregisterDeviceListener, TestSize.Level1)
{
    auto listener1 = new (std::nothrow) Input_DeviceListener();
    if (listener1 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
        return;
    }
    listener1->OnDeviceAdded = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceAdded1: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    listener1->OnDeviceRemoved = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceRemoved1: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener1), INPUT_SUCCESS);

    auto listener2 = new (std::nothrow) Input_DeviceListener();
    if (listener2 == nullptr) {
        MMI_HILOGE("Failed to new Input_DeviceListener");
        return;
    }
    listener2->OnDeviceAdded = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceAdded2: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    listener2->OnDeviceRemoved = [](int32_t deviceId, int32_t* deviceTypes, int32_t count) {
        MMI_HILOGI("OnDeviceRemoved2: deviceId: %d", deviceId);
        if (deviceTypes == nullptr || count <= 0) {
            return;
        }
        for (int32_t i = 0; i < count; i++) {
            MMI_HILOGI("deviceType: %d", deviceTypes[i]);
        }
    };
    EXPECT_EQ(OH_Input_RegisterDeviceListener(listener2), INPUT_SUCCESS);
    EXPECT_EQ(OH_Input_UnregisterDeviceListener(), INPUT_SUCCESS);
    delete listener1;
    delete listener2;
}
} // namespace MMI
} // namespace OHOS