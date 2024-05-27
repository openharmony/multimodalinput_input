/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "general_stylus.h"
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "libinput_wrapper.h"
#include "tablet_tool_tranform_processor.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletToolTranformProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class TabletToolTranformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void UpdateDisplayInfo();

private:
    static void SetupStylus();
    static void CloseStylus();
    static GeneralStylus vStylus_;
    static LibinputWrapper libinput_;
};

GeneralStylus TabletToolTranformProcessorTest::vStylus_;
LibinputWrapper TabletToolTranformProcessorTest::libinput_;

void TabletToolTranformProcessorTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupStylus();
    UpdateDisplayInfo();
}

void TabletToolTranformProcessorTest::TearDownTestCase(void)
{
    CloseStylus();
}

void TabletToolTranformProcessorTest::SetupStylus()
{
    ASSERT_TRUE(vStylus_.SetUp());
    std::cout << "device node name: " << vStylus_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vStylus_.GetDevPath()));
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
    struct libinput_device *device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
    InputDevMgr->OnInputDeviceAdded(device);
}

void TabletToolTranformProcessorTest::CloseStylus()
{
    libinput_.RemovePath(vStylus_.GetDevPath());
    vStylus_.Close();
}

void TabletToolTranformProcessorTest::UpdateDisplayInfo()
{
    auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    ASSERT_TRUE(display != nullptr);
    DisplayGroupInfo displays {
        .width = display->GetWidth(),
        .height = display->GetHeight(),
        .focusWindowId = -1,
    };
    displays.displaysInfo.push_back(DisplayInfo {
        .name = "default display",
        .width = display->GetWidth(),
        .height = display->GetHeight(),
    });
    WinMgr->UpdateDisplayInfo(displays);
}

void TabletToolTranformProcessorTest::SetUp()
{
}

void TabletToolTranformProcessorTest::TearDown()
{
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnEvent_001
 * @tc.desc: Verify that TabletToolTranformProcessor can correctly handle events when receive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    std::shared_ptr<PointerEvent> ret = processor.OnEvent(event);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTip_001
 * @tc.desc: Tablet tool transformation processor test, testing under the tip function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTip_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    bool ret = processor.OnTip(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipDown_001
 * @tc.desc: Test the OnTipDown method in the TabletToolTranformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool *event = nullptr;
    bool ret = processor.OnTipDown(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipMotion_001
 * @tc.desc: Test the response of TabletToolTranformProcessor when the tip is moving
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipMotion_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    bool ret = processor.OnTipMotion(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipUp_001
 * @tc.desc: Test case for the OnTipUp method of the TabletToolTranformProcessor class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TabletToolTransformProcessor processor(deviceId);
    libinput_event_tablet_tool *event = nullptr;
    bool ret = processor.OnTipUp(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnEvent_002
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vStylus_.SendEvent(EV_ABS, ABS_X, 8985);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6527);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 34);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 14);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8896);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6528);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8597);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6530);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8599);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6531);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 35);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9531);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 5727);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 39);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9438);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 20);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9345);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9339);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 5729);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 18);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 0);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 0);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 0);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 0);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = nullptr;
    auto ret = processor.OnEvent(event);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnEvent_003
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vStylus_.SendEvent(EV_ABS, ABS_X, 8985);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6527);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 34);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 14);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    auto ret = processor.OnEvent(event);
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTip_002
 * @tc.desc: Test OnTip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTip_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vStylus_.SendEvent(EV_ABS, ABS_X, 8985);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6527);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 34);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 14);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    bool ret = processor.OnTip(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipMotion_002
 * @tc.desc: Test OnTipMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipMotion_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vStylus_.SendEvent(EV_ABS, ABS_X, 8985);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6527);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 34);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 14);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    bool ret = processor.OnTip(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_GetToolType_001
 * @tc.desc: Test GetToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_GetToolType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vStylus_.SendEvent(EV_ABS, ABS_X, 8985);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6527);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 34);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 14);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8896);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6528);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8597);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6530);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8599);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6531);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 35);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9531);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 5727);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 39);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9438);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 20);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9345);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9339);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 5729);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 18);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 0);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 0);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 0);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 0);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    ASSERT_TRUE(tabletEvent != nullptr);
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    int32_t ret = processor.GetToolType(tabletEvent);
    ASSERT_EQ(ret, PointerEvent::TOOL_TYPE_PEN);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipDown_002
 * @tc.desc: Test OnTipDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vStylus_.SendEvent(EV_ABS, ABS_X, 8985);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6527);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 34);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 14);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    ASSERT_TRUE(tabletEvent != nullptr);
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    bool ret = processor.OnTipDown(tabletEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TabletToolTranformProcessorTest_OnTipUp_002
 * @tc.desc: Test OnTipUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TabletToolTranformProcessorTest, TabletToolTranformProcessorTest_OnTipUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vStylus_.SendEvent(EV_ABS, ABS_X, 8985);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6527);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 34);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 14);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8896);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6528);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8597);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6530);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 8599);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 6531);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 35);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9531);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 5727);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 39);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9438);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 20);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9345);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 9339);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 5729);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 18);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vStylus_.SendEvent(EV_ABS, ABS_X, 0);
    vStylus_.SendEvent(EV_ABS, ABS_Y, 0);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_X, 0);
    vStylus_.SendEvent(EV_ABS, ABS_TILT_Y, 0);
    vStylus_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    ASSERT_TRUE(tabletEvent != nullptr);
    int32_t deviceId = 2;
    TabletToolTransformProcessor processor(deviceId);
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.pointerEvent_ != nullptr);
    bool ret = processor.OnTipUp(tabletEvent);
    ASSERT_FALSE(ret);
}
}
}