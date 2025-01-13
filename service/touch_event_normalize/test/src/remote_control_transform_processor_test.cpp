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
#include "general_uwb_remote_control.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"
#include "libinput-private.h"
#include "libinput_wrapper.h"
#include "remote_control_transform_processor.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t POINTER_MOVEFLAG = { 7 };
} // namespace

class RemoteControlTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    
private:
    static void SetupUwbRemoteControl();
    static void CloseUwbRemoteControl();
    static GeneralUwbRemoteControl vUwbRemoteControl_;
    static LibinputWrapper libinput_;
};

GeneralUwbRemoteControl RemoteControlTransformProcessorTest::vUwbRemoteControl_;
LibinputWrapper RemoteControlTransformProcessorTest::libinput_;

void RemoteControlTransformProcessorTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupUwbRemoteControl();
}

void RemoteControlTransformProcessorTest::TearDownTestCase(void)
{
    CloseUwbRemoteControl();
}


void RemoteControlTransformProcessorTest::SetupUwbRemoteControl()
{
    ASSERT_TRUE(vUwbRemoteControl_.SetUp());
    std::cout << "device node name: " << vUwbRemoteControl_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vUwbRemoteControl_.GetDevPath()));
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
    struct libinput_device *device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
}


void RemoteControlTransformProcessorTest::CloseUwbRemoteControl()
{
    libinput_.RemovePath(vUwbRemoteControl_.GetDevPath());
    vUwbRemoteControl_.Close();
}

void RemoteControlTransformProcessorTest::SetUp()
{
}

void RemoteControlTransformProcessorTest::TearDown()
{
}

/**
 * @tc.name: Remote_ControlTransformProcessorTest_InitToolTypes_001
 * @tc.desc: Test the funcation InitToolTypes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTest, InitToolTypes_001, TestSize.Level1)
{
    int32_t deviceId = 7;
    Remote_ControlTransformProcessor processor(deviceId);
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
 * @tc.name: Remote_ControlTransformProcessorTest_OnEvent_001
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTest, Remote_ControlTransformProcessorTest_OnEvent_001,
        TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_.DrainEvents();
    int32_t deviceId = 7;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    int32_t varMoveFlag = POINTER_MOVEFLAG;
    std::cout << "varMoveFlag: " << POINTER_MOVEFLAG << std::endl;
    for (int32_t index = 1; index < POINTER_MOVEFLAG; ++index) {
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 5190 + index*30);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 8306);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 321);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_MOVEFLAG, varMoveFlag);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 198);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 180);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -64);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
        vUwbRemoteControl_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
        vUwbRemoteControl_.SendEvent(EV_KEY, BTN_TOUCH, 0);
        vUwbRemoteControl_.SendEvent(EV_SYN, SYN_REPORT, 0);
    }
    libinput_event* event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    while (event != nullptr) {
        auto type = libinput_event_get_type(event);
        if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
            event = libinput_.Dispatch();
            continue;
        }
        std::cout << "type: " << type << std::endl;
        auto touch = libinput_event_get_touch_event(event);
        ASSERT_TRUE(touch != nullptr);
        int32_t moveFlag = libinput_event_touch_get_move_flag(touch);
        std::cout << "moveFlag: " << moveFlag << std::endl;
        auto dev = libinput_event_get_device(event);
        ASSERT_TRUE(dev != nullptr);
        std::cout << "touch device: " << libinput_device_get_name(dev) << std::endl;
        EXPECT_NO_FATAL_FAILURE(processor.OnEvent(event));
        event = libinput_.Dispatch();
    }
}

/**
 * @tc.name: Remote_ControlTransformProcessorTest_OnEventTouchMotion_001
 * @tc.desc: Test the funcation OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTest, Remote_ControlTransformProcessorTest_OnEventTouchMotion_001,
        TestSize.Level1)
{
    int32_t deviceId = 7;
    Remote_ControlTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchMotion(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: Remote_ControlTransformProcessorTest_OnEventTouchMotion_002
 * @tc.desc: Test the funcation OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteControlTransformProcessorTest, Remote_ControlTransformProcessorTest_OnEventTouchMotion_002,
        TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_.DrainEvents();
    int32_t deviceId = 7;
    Remote_ControlTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    int32_t varMoveFlag = POINTER_MOVEFLAG;
    std::cout << "moveflag: " << varMoveFlag << std::endl;
    for (int32_t index = 1; index < POINTER_MOVEFLAG; ++index) {
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 5190);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 8306);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_PRESSURE, 321);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_MOVEFLAG, varMoveFlag);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_TOUCH_MAJOR, 198);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_TOUCH_MINOR, 180);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_ORIENTATION, -64);
        vUwbRemoteControl_.SendEvent(EV_ABS, ABS_MT_BLOB_ID, 2);
        vUwbRemoteControl_.SendEvent(EV_SYN, SYN_MT_REPORT, 0);
        vUwbRemoteControl_.SendEvent(EV_KEY, BTN_TOUCH, 0);
        vUwbRemoteControl_.SendEvent(EV_SYN, SYN_REPORT, 0);
    }
    libinput_event* event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    while (event != nullptr) {
        auto type = libinput_event_get_type(event);
        if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
            event = libinput_.Dispatch();
            continue;
        }
        std::cout << "type: " << type << std::endl;
        auto touch = libinput_event_get_touch_event(event);
        ASSERT_TRUE(touch != nullptr);
        int32_t moveFlag = libinput_event_touch_get_move_flag(touch);
        std::cout << "moveflag: " << moveFlag << std::endl;
        ASSERT_EQ(moveFlag, varMoveFlag);
        struct libinput_device *dev = libinput_event_get_device(event);
        ASSERT_TRUE(dev != nullptr);
        std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
        EXPECT_NO_FATAL_FAILURE(processor.OnEventTouchMotion(event));
        event = libinput_.Dispatch();
    }
}
} // namespace MMI
} // namespace OHOS