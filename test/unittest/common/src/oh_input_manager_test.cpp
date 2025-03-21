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
     int32_t action;
     int32_t keyCode;
     int64_t actionTime { -1 };
     int32_t windowId { -1 };
     int32_t displayId { -1 };
 };
 
 struct Input_MouseEvent {
     int32_t action;
     int32_t displayX;
     int32_t displayY;
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
     int64_t actionTime { -1 };
     int32_t windowId { -1 };
     int32_t displayId { -1 };
 };
 
 struct Input_AxisEvent {
     int32_t axisAction;
     float displayX;
     float displayY;
     std::map<int32_t, double> axisValues;
     int64_t actionTime { -1 };
     int32_t sourceType;
     int32_t axisEventType { -1 };
     int32_t windowId { -1 };
     int32_t displayId { -1 };
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
     Input_AxisEvent* inputAxisEvent = nullptr;
     EXPECT_EQ(OH_Input_DestroyAxisEvent(&inputAxisEvent), INPUT_PARAMETER_ERROR);
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
         return;
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
         return;
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
         return;
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
         return;
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
     Input_DeviceListener* listener = nullptr;
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
     int32_t deviceIds[inSize] = { 0 };
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
 
 static void HotkeyCallback(Input_Hotkey* hotkey)
 {}
 
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
     int32_t preKeys[] { KEYCODE_CTRL_LEFT };
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
  * @tc.name: OHInputManagerTest_OH_Input_GetFunctionKeyState
  * @tc.desc: Test the funcation OH_Input_GetFunctionKeyState
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(OHInputManagerTest, OHInputManagerTest_OH_Input_GetFunctionKeyState_001, TestSize.Level1)
 {
     int32_t keyCode = 1;
     int32_t state = -1;
     Input_Result retResult = OH_Input_GetFunctionKeyState(keyCode, &state);
     EXPECT_EQ(retResult, INPUT_SUCCESS);
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
     EXPECT_EQ(OH_Input_InjectTouchEvent(&inputTouchEvent), INPUT_PARAMETER_ERROR);
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
     int32_t prekeys[2] = { KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT };
     OH_Input_SetPreKeys(hotkey, prekeys, 2);
     int32_t key = 0;
     int32_t key1 = 0;
     int32_t *pressedKeys[2] = { &key, &key1 };
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
     int32_t prekeys[2] = { KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT };
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
 } // namespace MMI
 } // namespace OHOS