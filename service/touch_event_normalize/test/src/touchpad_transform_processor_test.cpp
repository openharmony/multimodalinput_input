/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <libinput.h>

#include "define_multimodal.h"
#include "general_touchpad.h"
#include "input_device_manager.h"
#include "libinput_wrapper.h"
#include "touchpad_transform_processor.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadTransformProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class TouchPadTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    static void SetupTouchpad();
    static void CloseTouchpad();

    static GeneralTouchpad vTouchpad_;
    static LibinputWrapper libinput_;
    int32_t trackingID_ { 0 };
    int32_t preScrollRows_ { 3 };

    TouchPadTransformProcessor g_processor_ { 0 };
    bool prePinchSwitch_ { true };
    bool preSwipeSwitch_ { true };
    bool preRotateSwitch_ { true };
};

GeneralTouchpad TouchPadTransformProcessorTest::vTouchpad_;
LibinputWrapper TouchPadTransformProcessorTest::libinput_;

void TouchPadTransformProcessorTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupTouchpad();
}

void TouchPadTransformProcessorTest::TearDownTestCase(void)
{
    CloseTouchpad();
}

void TouchPadTransformProcessorTest::SetupTouchpad()
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

void TouchPadTransformProcessorTest::CloseTouchpad()
{
    libinput_.RemovePath(vTouchpad_.GetDevPath());
    vTouchpad_.Close();
}

void TouchPadTransformProcessorTest::SetUp()
{
    g_processor_.GetTouchpadPinchSwitch(prePinchSwitch_);
    g_processor_.GetTouchpadSwipeSwitch(preSwipeSwitch_);
    g_processor_.GetTouchpadRotateSwitch(preRotateSwitch_);
    g_processor_.GetTouchpadScrollRows();
}

void TouchPadTransformProcessorTest::TearDown()
{
    g_processor_.SetTouchpadPinchSwitch(prePinchSwitch_);
    g_processor_.SetTouchpadSwipeSwitch(preSwipeSwitch_);
    g_processor_.SetTouchpadRotateSwitch(preRotateSwitch_);
    g_processor_.SetTouchpadScrollRows(preScrollRows_);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchpadPinchSwitch_01
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchpadPinchSwitch_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadPinchSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchpadPinchSwitch_02
 * @tc.desc: Test GetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchpadPinchSwitch_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    processor.SetTouchpadPinchSwitch(flag);
    bool newFlag = false;
    processor.GetTouchpadPinchSwitch(flag);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchpadSwipeSwitch_03
 * @tc.desc: Test SetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchpadSwipeSwitch_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadSwipeSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchpadSwipeSwitch_04
 * @tc.desc: Test GetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchpadSwipeSwitch_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool flag = false;
    processor.SetTouchpadSwipeSwitch(flag);
    bool newFlag = false;
    processor.GetTouchpadSwipeSwitch(flag);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchpadRotateSwitch_05
 * @tc.desc: Test SetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchpadRotateSwitch_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool rotateSwitch = false;
    ASSERT_TRUE(processor.SetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchpadRotateSwitch_06
 * @tc.desc: Test GetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchpadRotateSwitch_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    bool rotateSwitch = false;
    processor.SetTouchpadRotateSwitch(rotateSwitch);
    bool newRotateSwitch = false;
    processor.GetTouchpadRotateSwitch(newRotateSwitch);
    ASSERT_TRUE(rotateSwitch == newRotateSwitch);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchPadMultiTapData
 * @tc.desc: Test SetTouchPadMultiTapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchPadMultiTapData, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    ASSERT_NO_FATAL_FAILURE(processor.SetTouchPadMultiTapData());
}

/**
 * @tc.name: TouchPadTransformProcessorTest_ProcessTouchPadPinchDataEvent
 * @tc.desc: Test ProcessTouchPadPinchDataEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_ProcessTouchPadPinchDataEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    int32_t fingerCount = 2;
    int32_t action = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    double scale = 8.5;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(processor.pointerEvent_, nullptr);
    processor.pointerEvent_->SetFingerCount(2);
    ASSERT_NO_FATAL_FAILURE(processor.ProcessTouchPadPinchDataEvent(fingerCount, action, scale));

    fingerCount = 1;
    processor.pointerEvent_->SetFingerCount(1);
    ASSERT_NO_FATAL_FAILURE(processor.ProcessTouchPadPinchDataEvent(fingerCount, action, scale));

    fingerCount = 3;
    ASSERT_NO_FATAL_FAILURE(processor.ProcessTouchPadPinchDataEvent(fingerCount, action, scale));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_HandleMulFingersTap_001
 * @tc.desc: Verify if the multi-touch gesture handling is correct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_HandleMulFingersTap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MultiFingersTapHandler processor;
    libinput_event_touch *event = nullptr;
    int32_t type = 1;
    auto ret = processor.HandleMulFingersTap(event, type);
    ASSERT_EQ(ret, RET_ERR);
    ASSERT_NO_FATAL_FAILURE(processor.GetMultiFingersState());
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetMULTI_FINGERTAP_HDRDefault_001
 * @tc.desc: Test the behavior of SetMULTI_FINGERTAP_HDRDefault
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, SetMULTI_FINGERTAP_HDRDefault_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MultiFingersTapHandler processor;
    bool isAlldefault = true;
    ASSERT_NO_FATAL_FAILURE(processor.SetMULTI_FINGERTAP_HDRDefault(isAlldefault));
    isAlldefault = false;
    ASSERT_NO_FATAL_FAILURE(processor.SetMULTI_FINGERTAP_HDRDefault(isAlldefault));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_ClearPointerItems_001
 * @tc.desc: Verifying the ability to correctly clear pointer items under given conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_ClearPointerItems_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MultiFingersTapHandler processor;
    auto pointer = PointerEvent::Create();
    bool ret = processor.ClearPointerItems(pointer);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_PutConfigDataToDatabase_001
 * @tc.desc: Verify if the function of storing configuration data to the database works correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_PutConfigDataToDatabase_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    std::string key = "testKey";
    bool value = true;
    int32_t ret = processor.PutConfigDataToDatabase(key, value);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_PutConfigDataToDatabase_002
 * @tc.desc: Verify if the function of storing configuration data to the database works correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_PutConfigDataToDatabase_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    std::string key = "testKey";
    bool value = false;
    int32_t ret = processor.PutConfigDataToDatabase(key, value);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetConfigDataFromDatabase_001
 * @tc.desc: Verify if the functionality of getting configuration data from the database works correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetConfigDataFromDatabase_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    std::string key = "testKey";
    bool value = false;
    ASSERT_NO_FATAL_FAILURE(processor.GetConfigDataFromDatabase(key, value));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetConfigDataFromDatabase_002
 * @tc.desc: Test the GetConfigDataFromDatabase method of the TouchPadTransformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetConfigDataFromDatabase_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    std::string key = "testKey";
    bool value = true;
    ASSERT_NO_FATAL_FAILURE(processor.GetConfigDataFromDatabase(key, value));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEventTouchPadDown_001
 * @tc.desc: Verify the correctness of touchpad down event processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEventTouchPadDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    int32_t ret = processor.OnEventTouchPadDown(event);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEventTouchPadMotion_001
 * @tc.desc: Test the ability of the touchpad motion event processing function to handle normal input situations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEventTouchPadMotion_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    int32_t ret = processor.OnEventTouchPadMotion(event);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEventTouchPadMotion_002
 * @tc.desc: Test the ability of the touchpad motion event processing function to handle normal input situations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEventTouchPadMotion_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    processor.pointerEvent_->UpdatePointerItem(0, item);
    int32_t ret = processor.OnEventTouchPadMotion(event);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEventTouchPadUp_001
 * @tc.desc: Verify the correctness of touchpad up event processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEventTouchPadUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    processor.pointerEvent_->UpdatePointerItem(0, item);
    int32_t ret = processor.OnEventTouchPadUp(event);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEventTouchPadUp_002
 * @tc.desc: Verify the correctness of touchpad up event processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEventTouchPadUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    int32_t ret = processor.OnEventTouchPadUp(event);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEventTouchPadUp_003
 * @tc.desc: Verify the correctness of touchpad up event processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEventTouchPadUp_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    MULTI_FINGERTAP_HDR->multiFingersState_ = MulFingersTap::TRIPLETAP;
    int32_t ret = processor.OnEventTouchPadUp(event);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEvent_001
 * @tc.desc: test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    auto pointerEvent = processor.OnEvent(event);
    ASSERT_TRUE(pointerEvent == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEvent_002
 * @tc.desc: test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDeviceId(deviceId);
    processor.pointerEvent_->SetDeviceId(deviceId);
    processor.pointerEvent_->UpdatePointerItem(0, item);
    auto pointerEvent = processor.OnEvent(event);
    ASSERT_TRUE(pointerEvent != nullptr);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    while (event != nullptr) {
        event = libinput_.Dispatch();
    }
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEvent_003
 * @tc.desc: test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 763);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 663);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 2);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDeviceId(deviceId);
    processor.pointerEvent_->SetDeviceId(deviceId);
    processor.pointerEvent_->UpdatePointerItem(0, item);
    auto pointerEvent = processor.OnEvent(event);
    ASSERT_TRUE(pointerEvent != nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEvent_004
 * @tc.desc: test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDeviceId(deviceId);
    processor.pointerEvent_->SetDeviceId(deviceId);
    processor.pointerEvent_->UpdatePointerItem(0, item);
    auto pointerEvent = processor.OnEvent(event);
    ASSERT_TRUE(pointerEvent != nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchPadToolType_001
 * @tc.desc: test GetTouchPadToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchPadToolType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 703);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 603);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    ASSERT_NO_FATAL_FAILURE(processor.GetTouchPadToolType(touchpad, dev));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchPadToolType_002
 * @tc.desc: test GetTouchPadToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchPadToolType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 773);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 673);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    ASSERT_NO_FATAL_FAILURE(processor.GetTouchPadToolType(touchpad, dev));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchPadToolType_003
 * @tc.desc: test GetTouchPadToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchPadToolType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 783);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 683);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 1);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    ASSERT_NO_FATAL_FAILURE(processor.GetTouchPadToolType(touchpad, dev));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchPadToolType_004
 * @tc.desc: test GetTouchPadToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchPadToolType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 793);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 693);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TOOL_TYPE, 3);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    ASSERT_NO_FATAL_FAILURE(processor.GetTouchPadToolType(touchpad, dev));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchPadToolType_005
 * @tc.desc: test GetTouchPadToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchPadToolType_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 693);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 593);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.InitToolType();
    ASSERT_NO_FATAL_FAILURE(processor.GetTouchPadToolType(dev));
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    while (event != nullptr) {
        event = libinput_.Dispatch();
    }
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchPadToolType_006
 * @tc.desc: test GetTouchPadToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchPadToolType_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, ++trackingID_);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 763);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 663);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_RUBBER, 1);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.InitToolType();
    ASSERT_NO_FATAL_FAILURE(processor.GetTouchPadToolType(dev));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchPadSwipeData_001
 * @tc.desc: test SetTouchPadSwipeData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchPadSwipeData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 666);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 555);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.SetTouchpadSwipeSwitch(false);
    int32_t action = PointerEvent::POINTER_ACTION_SWIPE_BEGIN;
    ASSERT_NO_FATAL_FAILURE(processor.SetTouchPadSwipeData(event, action));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchPadSwipeData_002
 * @tc.desc: test SetTouchPadSwipeData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchPadSwipeData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 555);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 444);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.SetTouchpadSwipeSwitch(true);
    int32_t action = PointerEvent::POINTER_ACTION_SWIPE_BEGIN;
    ASSERT_NO_FATAL_FAILURE(processor.SetTouchPadSwipeData(event, action));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_CanAddToPointerMaps_001
 * @tc.desc: test CanAddToPointerMaps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_CanAddToPointerMaps_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 511);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 411);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    MultiFingersTapHandler processor;
    ASSERT_NO_FATAL_FAILURE(processor.CanAddToPointerMaps(touchpad));
    ASSERT_NO_FATAL_FAILURE(processor.CanAddToPointerMaps(touchpad));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_OnEventTouchPadPinch_001
 * @tc.desc: test OnEventTouchPadPinchBegin OnEventTouchPadPinchUpdate OnEventTouchPadPinchEnd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_OnEventTouchPadPinch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 66);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 77);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    ASSERT_NO_FATAL_FAILURE(processor.OnEventTouchPadPinchBegin(event));
    ASSERT_NO_FATAL_FAILURE(processor.OnEventTouchPadPinchUpdate(event));
    ASSERT_NO_FATAL_FAILURE(processor.OnEventTouchPadPinchEnd(event));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchPadPinchData_001
 * @tc.desc: test SetTouchPadPinchData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchPadPinchData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 166);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 155);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "touchpad device: " << libinput_device_get_name(dev) << std::endl;
    auto iter = INPUT_DEV_MGR->inputDevice_.begin();
    for (; iter != INPUT_DEV_MGR->inputDevice_.end(); ++iter) {
        if (iter->second.inputDeviceOrigin == dev) {
            break;
        }
    }
    ASSERT_TRUE(iter != INPUT_DEV_MGR->inputDevice_.end());
    int32_t deviceId = iter->first;
    TouchPadTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    processor.SetTouchpadSwipeSwitch(false);
    int32_t action = PointerEvent::POINTER_ACTION_SWIPE_BEGIN;
    ASSERT_NO_FATAL_FAILURE(processor.SetTouchPadPinchData(event, action));
    ASSERT_NO_FATAL_FAILURE(processor.SetPinchPointerItem(111222));
}

/**
 * @tc.name: TouchPadTransformProcessorTest_HandleMulFingersTap_002
 * @tc.desc: Verify if the multi-touch gesture handling is correct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_HandleMulFingersTap_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 266);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 255);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    MultiFingersTapHandler processor;
    processor.tapTrends_ = MultiFingersTapHandler::TapTrends::NOMULTAP;
    int32_t type = LIBINPUT_EVENT_TOUCHPAD_DOWN;
    auto ret = processor.HandleMulFingersTap(touchpad, type);
    ASSERT_EQ(ret, RET_OK);

    processor.tapTrends_ = MultiFingersTapHandler::TapTrends::BEGIN;
    ret = processor.HandleMulFingersTap(touchpad, type);
    ASSERT_EQ(ret, RET_OK);

    processor.tapTrends_ = MultiFingersTapHandler::TapTrends::DOWNING;
    auto time = libinput_event_touchpad_get_time_usec(touchpad);
    processor.lastTime = time - 150 * 1e3 - 1;
    ret = processor.HandleMulFingersTap(touchpad, type);
    ASSERT_EQ(ret, RET_OK);

    processor.tapTrends_ = MultiFingersTapHandler::TapTrends::UPING;
    processor.lastTime = time;
    processor.beginTime = time;
    ret = processor.HandleMulFingersTap(touchpad, type);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_HandleMulFingersTap_003
 * @tc.desc: Verify if the multi-touch gesture handling is correct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_HandleMulFingersTap_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 299);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 260);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    MultiFingersTapHandler processor;
    processor.tapTrends_ = MultiFingersTapHandler::TapTrends::UPING;
    auto time = libinput_event_touchpad_get_time_usec(touchpad);
    processor.lastTime = time;
    processor.beginTime = time;
    int32_t type = LIBINPUT_EVENT_TOUCHPAD_UP;
    processor.CanUnsetPointerItem(touchpad);
    auto ret = processor.HandleMulFingersTap(touchpad, type);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_HandleMulFingersTap_004
 * @tc.desc: Verify if the multi-touch gesture handling is correct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_HandleMulFingersTap_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 311);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 270);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    MultiFingersTapHandler processor;
    processor.tapTrends_ = MultiFingersTapHandler::TapTrends::UPING;
    auto time = libinput_event_touchpad_get_time_usec(touchpad);
    processor.lastTime = time;
    processor.beginTime = time;
    int32_t type = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    auto ret = processor.HandleMulFingersTap(touchpad, type);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_HandleMulFingersTap_005
 * @tc.desc: Verify if the multi-touch gesture handling is correct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_HandleMulFingersTap_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 299);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 260);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    MultiFingersTapHandler processor;
    processor.tapTrends_ = MultiFingersTapHandler::TapTrends::UPING;
    auto time = libinput_event_touchpad_get_time_usec(touchpad);
    processor.lastTime = time;
    processor.beginTime = time;
    int32_t type = LIBINPUT_EVENT_TOUCHPAD_UP;
    processor.CanUnsetPointerItem(touchpad);
    processor.downCnt = 3;
    processor.upCnt = 2;
    auto ret = processor.HandleMulFingersTap(touchpad, type);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_SetTouchpadScrollRows_001
 * @tc.desc: Test SetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_SetTouchpadScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    TouchPadTransformProcessor processor(deviceId);
    int32_t rows = 1;
    ASSERT_TRUE(processor.SetTouchpadScrollRows(rows) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorTest_GetTouchpadScrollRows_002
 * @tc.desc: Test GetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorTest, TouchPadTransformProcessorTest_GetTouchpadScrollRows_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    TouchPadTransformProcessor processor(deviceId);
    int32_t rows = 1;
    processor.SetTouchpadScrollRows(rows);
    int32_t newRows = processor.GetTouchpadScrollRows();
    ASSERT_TRUE(rows == newRows);
}
} // namespace MMI
} // namespace OHOS