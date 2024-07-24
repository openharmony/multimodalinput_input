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
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "general_touchscreen.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"
#include "libinput-private.h"
#include "libinput_wrapper.h"
#include "touch_transform_processor.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class TouchTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    
private:
    static void SetupTouchscreen();
    static void CloseTouchscreen();
    static GeneralTouchscreen vTouchscreen_;
    static LibinputWrapper libinput_;
};

GeneralTouchscreen TouchTransformProcessorTest::vTouchscreen_;
LibinputWrapper TouchTransformProcessorTest::libinput_;

void TouchTransformProcessorTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupTouchscreen();
}

void TouchTransformProcessorTest::TearDownTestCase(void)
{
    CloseTouchscreen();
}

void TouchTransformProcessorTest::SetupTouchscreen()
{
    ASSERT_TRUE(vTouchscreen_.SetUp());
    std::cout << "device node name: " << vTouchscreen_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vTouchscreen_.GetDevPath()));
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
    struct libinput_device *device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
}

void TouchTransformProcessorTest::CloseTouchscreen()
{
    libinput_.RemovePath(vTouchscreen_.GetDevPath());
    vTouchscreen_.Close();
}

void TouchTransformProcessorTest::SetUp()
{
}

void TouchTransformProcessorTest::TearDown()
{
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchDown_001
 * @tc.desc: Test the funcation OnEventTouchDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchDown_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchDown(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TouchTransformProcessorTest_UpdatePointerItemProperties_001
 * @tc.desc: Test the funcation UpdatePointerItemProperties
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, UpdatePointerItemProperties_001, TestSize.Level1)
{
    PointerEvent::PointerItem item;
    EventTouch touchInfo;
    touchInfo.point.x = 10;
    touchInfo.point.y = 20;
    touchInfo.toolRect.point.x = 30;
    touchInfo.toolRect.point.y = 40;
    touchInfo.toolRect.width = 50;
    touchInfo.toolRect.height = 60;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.UpdatePointerItemProperties(item, touchInfo);
    ASSERT_EQ(item.GetDisplayX(), touchInfo.point.x);
    ASSERT_EQ(item.GetDisplayY(), touchInfo.point.y);
    ASSERT_EQ(item.GetDisplayXPos(), touchInfo.point.x);
    ASSERT_EQ(item.GetDisplayYPos(), touchInfo.point.y);
    ASSERT_EQ(item.GetToolDisplayX(), touchInfo.toolRect.point.x);
    ASSERT_EQ(item.GetToolDisplayY(), touchInfo.toolRect.point.y);
    ASSERT_EQ(item.GetToolWidth(), touchInfo.toolRect.width);
    ASSERT_EQ(item.GetToolHeight(), touchInfo.toolRect.height);
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchMotion_001
 * @tc.desc: Test the funcation OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchMotion_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchMotion(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchUp_001
 * @tc.desc: Test the funcation OnEventTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchUp_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchUp(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TouchTransformProcessorTest_GetTouchToolType_001
 * @tc.desc: Test the funcation GetTouchToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, GetTouchToolType_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    struct libinput_device *device = nullptr;
    int32_t toolType = processor.GetTouchToolType(device);
    ASSERT_EQ(toolType, PointerEvent::TOOL_TYPE_FINGER);
}

/**
 * @tc.name: TouchTransformProcessorTest_InitToolTypes_001
 * @tc.desc: Test the funcation InitToolTypes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, InitToolTypes_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InitToolTypes();
    ASSERT_EQ(processor.vecToolType_.size(), 16);
    ASSERT_EQ(processor.vecToolType_[0].first, BTN_TOOL_PEN);
    ASSERT_EQ(processor.vecToolType_[0].second, PointerEvent::TOOL_TYPE_PEN);
    ASSERT_EQ(processor.vecToolType_[1].first, BTN_TOOL_RUBBER);
    ASSERT_EQ(processor.vecToolType_[1].second, PointerEvent::TOOL_TYPE_RUBBER);
    ASSERT_EQ(processor.vecToolType_[2].first, BTN_TOOL_BRUSH);
    ASSERT_EQ(processor.vecToolType_[2].second, PointerEvent::TOOL_TYPE_BRUSH);
    ASSERT_EQ(processor.vecToolType_[3].first, BTN_TOOL_PENCIL);
    ASSERT_EQ(processor.vecToolType_[3].second, PointerEvent::TOOL_TYPE_PENCIL);
    ASSERT_EQ(processor.vecToolType_[4].first, BTN_TOOL_AIRBRUSH);
    ASSERT_EQ(processor.vecToolType_[4].second, PointerEvent::TOOL_TYPE_AIRBRUSH);
    ASSERT_EQ(processor.vecToolType_[5].first, BTN_TOOL_FINGER);
    ASSERT_EQ(processor.vecToolType_[5].second, PointerEvent::TOOL_TYPE_FINGER);
    ASSERT_EQ(processor.vecToolType_[6].first, BTN_TOOL_MOUSE);
    ASSERT_EQ(processor.vecToolType_[6].second, PointerEvent::TOOL_TYPE_MOUSE);
    ASSERT_EQ(processor.vecToolType_[7].first, BTN_TOOL_LENS);
    ASSERT_EQ(processor.vecToolType_[7].second, PointerEvent::TOOL_TYPE_LENS);
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchDown_002
 * @tc.desc: Test the funcation OnEventTouchDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchDown(event);
    ASSERT_FALSE(ret);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 5190);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 8306);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 321);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 198);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 180);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -64);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchscreen_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touch = libinput_event_get_touch_event(event);
    ASSERT_TRUE(touch != nullptr);
    auto device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
    ret = processor.OnEventTouchDown(event);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TouchTransformProcessorTest_NotifyFingersenseProcess_001
 * @tc.desc: Test the funcation NotifyFingersenseProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, NotifyFingersenseProcess_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    PointerEvent::PointerItem item;
    int32_t toolType = 0;
    EXPECT_NO_FATAL_FAILURE(processor.NotifyFingersenseProcess(item, toolType));
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchMotion_002
 * @tc.desc: Test the funcation OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchMotion_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchMotion(event);
    ASSERT_FALSE(ret);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 5199);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 8297);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 356);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 216);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 162);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -79);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touch = libinput_event_get_touch_event(event);
    ASSERT_TRUE(touch != nullptr);
    EXPECT_NO_FATAL_FAILURE(processor.OnEventTouchMotion(event));
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchUp_002
 * @tc.desc: Test the funcation OnEventTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchUp(event);
    ASSERT_FALSE(ret);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 6486);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 7289);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 313);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 198);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 180);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -58);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchscreen_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touch = libinput_event_get_touch_event(event);
    ASSERT_TRUE(touch != nullptr);
    EXPECT_NO_FATAL_FAILURE(processor.OnEventTouchUp(event));
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEvent_001
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, TouchTransformProcessorTest_OnEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 5190);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 8306);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 321);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 198);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 180);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -64);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchscreen_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    TouchTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    auto ret = processor.OnEvent(event);
    ASSERT_FALSE(ret);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    EXPECT_NO_FATAL_FAILURE(processor.OnEvent(event));
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEvent_002
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, TouchTransformProcessorTest_OnEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 5199);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 8297);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 356);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 216);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 162);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -79);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    EXPECT_NO_FATAL_FAILURE(processor.OnEvent(event));
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEvent_003
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, TouchTransformProcessorTest_OnEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 6486);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 7289);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 313);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 198);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 180);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -58);
    vTouchscreen_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
    vTouchscreen_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
    vTouchscreen_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchscreen_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    EXPECT_NO_FATAL_FAILURE(processor.OnEvent(event));
}
} // namespace MMI
} // namespace OHOS