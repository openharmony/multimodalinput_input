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

#include "display_manager.h"

#include "general_mouse.h"
#include "general_touchpad.h"
#include "mouse_transform_processor.h"
#include "window_info.h"
#include "mouse_device_state.h"
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "i_input_windows_manager.h"
#include "libinput_wrapper.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t BTN_RIGHT_MENUE_CODE = 0x118;
constexpr int32_t HARD_HARDEN_DEVICE_WIDTH = 2880;
constexpr int32_t HARD_HARDEN_DEVICE_HEIGHT = 1920;
}
class MouseTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void SetupMouse();
    static void CloseMouse();
    static void UpdateDisplayInfo();
    void SetUp();
    void TearDown();

private:
    static GeneralMouse vMouse_;
    static GeneralTouchpad vTouchpad_ ;
    static LibinputWrapper libinput_;

    MouseTransformProcessor g_processor_ { 0 };
    int32_t prePointerSpeed_ { 5 };
    int32_t prePrimaryButton_ { 0 };
    int32_t preScrollRows_ { 3 };
    int32_t preTouchpadPointerSpeed_ { 9 };
    int32_t preRightClickType_ { 1 };
    bool preScrollSwitch_ { true };
    bool preScrollDirection_ { true };
    bool preTapSwitch_ { true };
};

GeneralMouse MouseTransformProcessorTest::vMouse_;
GeneralTouchpad MouseTransformProcessorTest::vTouchpad_;
LibinputWrapper MouseTransformProcessorTest::libinput_;

void MouseTransformProcessorTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupMouse();
    UpdateDisplayInfo();
}

void MouseTransformProcessorTest::TearDownTestCase(void)
{
    CloseMouse();
}

void MouseTransformProcessorTest::SetupMouse()
{
    ASSERT_TRUE(vMouse_.SetUp());
    std::cout << "device node name: " << vMouse_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vMouse_.GetDevPath()));

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

void MouseTransformProcessorTest::CloseMouse()
{
    libinput_.RemovePath(vMouse_.GetDevPath());
    vMouse_.Close();
    libinput_.RemovePath(vTouchpad_.GetDevPath());
    vTouchpad_.Close();
}

void MouseTransformProcessorTest::UpdateDisplayInfo()
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
    WIN_MGR->UpdateDisplayInfo(displays);
}

void MouseTransformProcessorTest::SetUp()
{
    prePointerSpeed_ = g_processor_.GetPointerSpeed();
    prePrimaryButton_ = g_processor_.GetMousePrimaryButton();
    preScrollRows_ = g_processor_.GetMouseScrollRows();
    g_processor_.GetTouchpadPointerSpeed(preTouchpadPointerSpeed_);
    g_processor_.GetTouchpadRightClickType(preRightClickType_);
    g_processor_.GetTouchpadScrollSwitch(preScrollSwitch_);
    g_processor_.GetTouchpadScrollDirection(preScrollDirection_);
    g_processor_.GetTouchpadTapSwitch(preTapSwitch_);
}

void MouseTransformProcessorTest::TearDown()
{
    g_processor_.SetPointerSpeed(prePointerSpeed_);
    g_processor_.SetMousePrimaryButton(prePrimaryButton_);
    g_processor_.SetMouseScrollRows(preScrollRows_);
    g_processor_.SetTouchpadPointerSpeed(preTouchpadPointerSpeed_);
    g_processor_.SetTouchpadRightClickType(preRightClickType_);
    g_processor_.SetTouchpadScrollSwitch(preScrollSwitch_);
    g_processor_.SetTouchpadScrollDirection(preScrollDirection_);
    g_processor_.SetTouchpadTapSwitch(preTapSwitch_);
}

/**
 * @tc.name: MouseTransformProcessorTest_DeletePressedButton_001
 * @tc.desc: Test DeletePressedButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_DeletePressedButton_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t originButton = 1;
    ASSERT_NO_FATAL_FAILURE(processor.DeletePressedButton(originButton));
}

/**
 * @tc.name: MouseTransformProcessorTest_DeletePressedButton_002
 * @tc.desc: Test DeletePressedButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_DeletePressedButton_002, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t originButton = 1;
    int32_t mappedButton = 2;
    processor.buttonMapping_[originButton] = mappedButton;
    ASSERT_NO_FATAL_FAILURE(processor.DeletePressedButton(originButton));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisAccelateTouchPad_001
 * @tc.desc: Test HandleAxisAccelateTouchPad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisAccelateTouchPad_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    double axisValue = 2.0;
    auto inputWindowsManager = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->captureModeInfo_.isCaptureMode = true;
    double ret = processor.HandleAxisAccelateTouchPad(axisValue);
    ASSERT_EQ(ret, 2.0);
    inputWindowsManager->captureModeInfo_.isCaptureMode = false;
    ret = processor.HandleAxisAccelateTouchPad(axisValue);
    ASSERT_EQ(ret, 2.14);
    axisValue = -5.0;
    ret = processor.HandleAxisAccelateTouchPad(axisValue);
    ASSERT_NE(ret, -5.0);
}

/**
 * @tc.name: MouseTransformProcessorTest_CheckDeviceType_01
 * @tc.desc: Test CheckDeviceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_CheckDeviceType_01, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t width = HARD_HARDEN_DEVICE_WIDTH;
    int32_t height = HARD_HARDEN_DEVICE_HEIGHT;
    ASSERT_NO_FATAL_FAILURE(processor.CheckDeviceType(width, height));
}

/**
 * @tc.name: MouseTransformProcessorTest_Dump_002
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_Dump_002, TestSize.Level1)
{
    std::vector<std::string> args;
    std::vector<std::string> idNames;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t fd = 0;
    processor.Dump(fd, args);
    ASSERT_EQ(args, idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_NormalizeMoveMouse_003
 * @tc.desc: Test NormalizeMoveMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_NormalizeMoveMouse_003, TestSize.Level1)
{
    bool isNormalize = true;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    ASSERT_EQ(processor.NormalizeMoveMouse(offsetX, offsetY), isNormalize);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetDisplayId_004
 * @tc.desc: Test GetDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetDisplayId_004, TestSize.Level1)
{
    int32_t idNames = 0;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    ASSERT_EQ(processor.GetDisplayId(), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerSpeed_005
 * @tc.desc: Test SetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerSpeed_005, TestSize.Level1)
{
    int32_t idNames = 0;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 5;
    ASSERT_EQ(processor.SetPointerSpeed(speed), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerSpeed_006
 * @tc.desc: Test GetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerSpeed_006, TestSize.Level1)
{
    int32_t idNames = 5;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 5;
    processor.SetPointerSpeed(speed);
    ASSERT_EQ(processor.GetPointerSpeed(), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerLocation_008
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerLocation_008, TestSize.Level1)
{
    int32_t idNames = 0;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t x = 0;
    int32_t y = 0;
    ASSERT_EQ(processor.SetPointerLocation(x, y), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerSpeed_009
 * @tc.desc: Test GetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerSpeed_009, TestSize.Level1)
{
    int32_t idNames = 1;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 0;
    processor.SetPointerSpeed(speed);
    ASSERT_EQ(processor.GetPointerSpeed(), idNames);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetMousePrimaryButton_010
 * @tc.desc: Test SetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetMousePrimaryButton_010, TestSize.Level1)
{
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    int32_t primaryButton = 1;
    ASSERT_TRUE(processor.SetMousePrimaryButton(primaryButton) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetMousePrimaryButton_011
 * @tc.desc: Test GetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetMousePrimaryButton_011, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t primaryButton = 1;
    processor.SetMousePrimaryButton(primaryButton);
    int32_t primaryButtonRes = 1;
    ASSERT_TRUE(processor.GetMousePrimaryButton() == primaryButtonRes);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetMouseScrollRows_012
 * @tc.desc: Test SetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetMouseScrollRows_012, TestSize.Level1)
{
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    int32_t rows = 1;
    ASSERT_TRUE(processor.SetMouseScrollRows(rows) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetMouseScrollRows_013
 * @tc.desc: Test GetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetMouseScrollRows_013, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t rows = 1;
    processor.SetMouseScrollRows(rows);
    int32_t newRows = 1;
    ASSERT_TRUE(processor.GetMouseScrollRows() == newRows);
}
/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadScrollSwitch_014
 * @tc.desc: Test SetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadScrollSwitch_014, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadScrollSwitch(flag) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadScrollSwitch_015
 * @tc.desc: Test GetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadScrollSwitch_015, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = true;
    processor.SetTouchpadScrollSwitch(flag);
    bool newFlag = true;
    processor.GetTouchpadScrollSwitch(flag);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadScrollSwitch_014
 * @tc.desc: Test SetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadScrollDirection_016, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool state = false;
    ASSERT_TRUE(processor.SetTouchpadScrollDirection(state) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadScrollDirection_017
 * @tc.desc: Test GetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadScrollDirection_017, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool state = true;
    processor.SetTouchpadScrollDirection(state);
    bool newState = true;
    processor.GetTouchpadScrollDirection(state);
    ASSERT_TRUE(state == newState);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadTapSwitch_018
 * @tc.desc: Test SetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadTapSwitch_018, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = false;
    ASSERT_TRUE(processor.SetTouchpadTapSwitch(flag) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadTapSwitch_019
 * @tc.desc: Test GetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadTapSwitch_019, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    bool flag = false;
    processor.SetTouchpadTapSwitch(flag);
    bool newFlag = false;
    processor.GetTouchpadTapSwitch(flag);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadPointerSpeed_020
 * @tc.desc: Test SetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadPointerSpeed_020, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 2;
    ASSERT_TRUE(processor.SetTouchpadPointerSpeed(speed) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadPointerSpeed_021
 * @tc.desc: Test GetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadPointerSpeed_021, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 2;
    processor.SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = 3;
    processor.GetTouchpadPointerSpeed(newSpeed);
    ASSERT_TRUE(speed == newSpeed);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadPointerSpeed_022
 * @tc.desc: Test SetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadPointerSpeed_022, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 8;
    ASSERT_TRUE(processor.SetTouchpadPointerSpeed(speed) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadPointerSpeed_023
 * @tc.desc: Test GetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadPointerSpeed_023, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = 8;
    processor.SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = 7;
    processor.GetTouchpadPointerSpeed(newSpeed);
    ASSERT_TRUE(speed == newSpeed);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetTouchpadRightClickType_024
 * @tc.desc: Test SetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetTouchpadRightClickType_024, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t type = 2;
    ASSERT_TRUE(processor.SetTouchpadRightClickType(type) == RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadRightClickType_025
 * @tc.desc: Test GetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadRightClickType_025, TestSize.Level1)
{
    int32_t deviceId = 6;
    MouseTransformProcessor processor(deviceId);
    int32_t type = 1;
    processor.SetTouchpadRightClickType(type);
    int32_t newType = 3;
    processor.GetTouchpadRightClickType(newType);
    ASSERT_TRUE(type == newType);
}

/**
 * @tc.name: MouseTransformProcessorTest_GetPointerEvent_001
 * @tc.desc: Get pointer event verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetPointerEvent_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    auto ret = processor.GetPointerEvent();
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleMotionInner_001
 * @tc.desc: Handle motion inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleMotionInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    struct libinput_event* event = nullptr;
    auto ret = processor.HandleMotionInner(data, event);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_CalculateOffset_001
 * @tc.desc: Calculate offset verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_CalculateOffset_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    Direction direction = DIRECTION90;
    Offset offset;
    ASSERT_NO_FATAL_FAILURE(processor.CalculateOffset(direction, offset));
}

/**
 * @tc.name: MouseTransformProcessorTest_CalculateOffset_002
 * @tc.desc: Calculate offset verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_CalculateOffset_002, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    Direction direction = DIRECTION180;
    Offset offset;
    ASSERT_NO_FATAL_FAILURE(processor.CalculateOffset(direction, offset));
}

/**
 * @tc.name: MouseTransformProcessorTest_CalculateOffset_003
 * @tc.desc: Calculate offset verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_CalculateOffset_003, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    Direction direction = DIRECTION270;
    Offset offset;
    ASSERT_NO_FATAL_FAILURE(processor.CalculateOffset(direction, offset));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonInner_001
 * @tc.desc: Handle button inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    struct libinput_event* event = nullptr;
    auto ret = processor.HandleButtonInner(data, event);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonValueInner_001
 * @tc.desc: Handle button value inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonValueInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    uint32_t button = -1;
    int32_t type = 0;
    auto ret = processor.HandleButtonValueInner(data, button, type);
    ASSERT_NE(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonValueInner_002
 * @tc.desc: Handle button value inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonValueInner_002, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    uint32_t button = 272;
    int32_t type = 1;
    auto ret = processor.HandleButtonValueInner(data, button, type);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchPadAxisState_001
 * @tc.desc: Handle touch pad axis state verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchPadAxisState_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    libinput_pointer_axis_source source = LIBINPUT_POINTER_AXIS_SOURCE_FINGER;
    int32_t direction = 0;
    bool tpScrollSwitch = false;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchPadAxisState(source, direction, tpScrollSwitch));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisInner_001
 * @tc.desc: Handle axis inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    auto ret = processor.HandleAxisInner(data);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisBeginEndInner_001
 * @tc.desc: Handle axis begin end inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisBeginEndInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event* event = nullptr;
    auto ret = processor.HandleAxisBeginEndInner(event);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisPostInner_001
 * @tc.desc: Handle axis post inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisPostInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    PointerEvent::PointerItem pointerItem;
    ASSERT_NO_FATAL_FAILURE(processor.HandleAxisPostInner(pointerItem));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandlePostInner_001
 * @tc.desc: Handle post inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandlePostInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    PointerEvent::PointerItem pointerItem;
    ASSERT_NO_FATAL_FAILURE(processor.HandlePostInner(data, pointerItem));
}

/**
 * @tc.name: MouseTransformProcessorTest_Normalize_001
 * @tc.desc: Normalize verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_Normalize_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event* event = nullptr;
    auto ret = processor.Normalize(event);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_NormalizeRotateEvent_001
 * @tc.desc: Normalize rotate event verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_NormalizeRotateEvent_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event* event = nullptr;
    int32_t type = 1;
    double angle = 90.0;
    auto ret = processor.NormalizeRotateEvent(event, type, angle);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleMotionMoveMouse_001
 * @tc.desc: Handle motion move mouse verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleMotionMoveMouse_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t offsetX = 10;
    int32_t offsetY = 20;
    ASSERT_NO_FATAL_FAILURE(processor.HandleMotionMoveMouse(offsetX, offsetY));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleMotionMoveMouse_002
 * @tc.desc: Handle motion move mouse verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleMotionMoveMouse_002, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t offsetX = -1000;
    int32_t offsetY = 500;
    ASSERT_NO_FATAL_FAILURE(processor.HandleMotionMoveMouse(offsetX, offsetY));
}

/**
 * @tc.name: MouseTransformProcessorTest_OnDisplayLost_001
 * @tc.desc: On display lost verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_OnDisplayLost_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t displayId = -1;
    ASSERT_NO_FATAL_FAILURE(processor.OnDisplayLost(displayId));
}

/**
 * @tc.name: MouseTransformProcessorTest_OnDisplayLost_002
 * @tc.desc: On display lost verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_OnDisplayLost_002, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t displayId = 1;
    ASSERT_NO_FATAL_FAILURE(processor.OnDisplayLost(displayId));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandlePostMoveMouse_001
 * @tc.desc: Handle post move mouse verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandlePostMoveMouse_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    PointerEvent::PointerItem pointerItem;
    ASSERT_NO_FATAL_FAILURE(processor.HandlePostMoveMouse(pointerItem));
}

/**
 * @tc.name: MouseTransformProcessorTest_DumpInner_001
 * @tc.desc: Dump inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_DumpInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    ASSERT_NO_FATAL_FAILURE(processor.DumpInner());
}

/**
 * @tc.name: MouseTransformProcessorTest_GetTouchpadSpeed_001
 * @tc.desc: Get touchpad speed verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_GetTouchpadSpeed_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    auto ret = processor.GetTouchpadSpeed();
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadRightButton_001
 * @tc.desc: Handle touchpad right button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadRightButton_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = 1;
    uint32_t button = 0x118;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadRightButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadRightButton_002
 * @tc.desc: Handle touchpad right button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadRightButton_002, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = LIBINPUT_EVENT_POINTER_TAP;
    uint32_t button = MouseDeviceState::LIBINPUT_RIGHT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadRightButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_Normalize_01
 * @tc.desc: Test the branch that handles mouse movement events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_Normalize_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    EXPECT_EQ(processor.Normalize(event), RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_Normalize_02
 * @tc.desc: Tests the branch that handles the left mouse button event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_Normalize_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_KEY, BTN_LEFT, 1);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    EXPECT_EQ(processor.Normalize(event), RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_NormalizeRotateEvent_01
 * @tc.desc: Test normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_NormalizeRotateEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t type = 1;
    double angle = 90.0;
    int32_t result = processor.NormalizeRotateEvent(event, type, angle);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_NormalizeRotateEvent_02
 * @tc.desc: Tests HandlePostInner return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_NormalizeRotateEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t type = 0;
    double angle = 0.0;
    std::shared_ptr<PointerEvent::PointerItem> pointerItem = nullptr;
    int32_t result = processor.NormalizeRotateEvent(event, type, angle);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadRightButton_003
 * @tc.desc: Handle touchpad right button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadRightButton_003, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadRightButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_001
 * @tc.desc: Handle touchpad left button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = 1;
    uint32_t button = 0x118;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_002
 * @tc.desc: Handle touchpad left button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_002, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = 1;
    uint32_t button = MouseDeviceState::LIBINPUT_RIGHT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_003
 * @tc.desc: Handle touchpad left button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_003, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = LIBINPUT_EVENT_POINTER_TAP;
    uint32_t button = MouseDeviceState::LIBINPUT_RIGHT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_004
 * @tc.desc: Handle touchpad left button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_004, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_TransTouchpadRightButton_01
 * @tc.desc: Trans touchpad right button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_TransTouchpadRightButton_01, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = LIBINPUT_EVENT_POINTER_TAP;
    uint32_t button = MouseDeviceState::LIBINPUT_RIGHT_BUTTON_CODE;
    processor.TransTouchpadRightButton(data, eventType, button);
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadRightButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_TransTouchpadRightButton_02
 * @tc.desc: Trans touchpad right button verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_TransTouchpadRightButton_02, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = LIBINPUT_EVENT_POINTER_TAP;
    uint32_t button = MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE;
    processor.TransTouchpadRightButton(data, eventType, button);
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisBeginEndInner_01
 * @tc.desc: Test HandleAxisBeginEndInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisBeginEndInner_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    bool isAxisBegin;
    bool isPressed;
    MouseTransformProcessor processor(deviceId);

    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);

    isAxisBegin = false;
    isPressed = true;
    int32_t ret = processor.HandleAxisBeginEndInner(event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisBeginEndInner_02
 * @tc.desc: Test HandleAxisBeginEndInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisBeginEndInner_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isAxisBegin;
    bool isPressed;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);

    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);

    isAxisBegin = true;
    isPressed = true;
    int32_t ret = processor.HandleAxisBeginEndInner(event);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisBeginEndInner_03
 * @tc.desc: Test HandleAxisBeginEndInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisBeginEndInner_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t buttonId;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);

    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);

    buttonId = PointerEvent::BUTTON_NONE;
    int32_t ret = processor.HandleAxisBeginEndInner(event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorTest_CheckAndPackageAxisEvent_001
 * @tc.desc: Test isAxisBegin is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_CheckAndPackageAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    processor.isAxisBegin_ = false;
    bool result = processor.CheckAndPackageAxisEvent();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MouseTransformProcessorTest_CheckAndPackageAxisEvent_002
 * @tc.desc: Test isAxisBegin is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_CheckAndPackageAxisEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    processor.isAxisBegin_ = true;
    bool result = processor.CheckAndPackageAxisEvent();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonValueInner_003
 * @tc.desc: The corresponding key type cannot be found in the test overlay buttonId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonValueInner_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto data = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(data != nullptr);
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    uint32_t button = 0;
    int32_t type = 2;
    int32_t ret = processor.HandleButtonValueInner(data, button, type);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonValueInner_004
 * @tc.desc: Test overwrite buttonId to find corresponding key type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonValueInner_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto data = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(data != nullptr);
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    uint32_t button = MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE;
    int32_t type = 2;
    int32_t ret = processor.HandleButtonValueInner(data, button, type);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonValueInner_005
 * @tc.desc: Test the case that the buttonId covers different key types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonValueInner_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto data = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(data != nullptr);
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    uint32_t button = MouseDeviceState::LIBINPUT_RIGHT_BUTTON_CODE;
    int32_t type = 2;
    int32_t ret = processor.HandleButtonValueInner(data, button, type);
    EXPECT_EQ(ret, RET_OK);
    button = MouseDeviceState::LIBINPUT_MIDDLE_BUTTON_CODE;
    ret = processor.HandleButtonValueInner(data, button, type);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleMotionInner_002
 * @tc.desc: Test HandleMotionInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleMotionInner_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto data = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(data != nullptr);
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t ret = processor.HandleMotionInner(data, event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleMotionInner_003
 * @tc.desc: Test HandleMotionInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleMotionInner_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto data = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(data != nullptr);
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    CursorPosition cursorPos;
    cursorPos.displayId = -1;
    int32_t type = LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    int32_t ret = processor.HandleMotionInner(data, event);
    EXPECT_EQ(ret, RET_OK);
    type = LIBINPUT_EVENT_POINTER_BUTTON;
    ret = processor.HandleMotionInner(data, event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonInner_002
 * @tc.desc: Test HandleButtonInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonInner_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto data = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(data != nullptr);
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    int32_t ret = processor.HandleButtonInner(data, event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchPadAxisState_01
 * @tc.desc: Test HandleTouchPadAxisState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchPadAxisState_01, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    libinput_pointer_axis_source source = LIBINPUT_POINTER_AXIS_SOURCE_FINGER;
    int32_t direction = 1;
    bool tpScrollSwitch = true;
    processor.HandleTouchPadAxisState(source, direction, tpScrollSwitch);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadRightButton_01
 * @tc.desc: Test HandleTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadRightButton_01, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_TAP;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadRightButton(data, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadRightButton_02
 * @tc.desc: Test HandleTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadRightButton_02, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_TAP;
    uint32_t button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadRightButton(data, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_01
 * @tc.desc: Test HandleTouchpadLeftButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_01, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_02
 * @tc.desc: Test HandleTouchpadLeftButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_02, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_03
 * @tc.desc: Test HandleTouchpadLeftButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_03, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_TAP;
    uint32_t button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_RIGHT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_04
 * @tc.desc: Test HandleTouchpadLeftButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_04, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = MouseDeviceState::LIBINPUT_BUTTON_CODE::LIBINPUT_LEFT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, evenType, button));
}

/**
 * @tc.name: MouseTransformProcessorTest_TransTouchpadRightButton_04
 * @tc.desc: Test TransTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_TransTouchpadRightButton_04, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_KEYBOARD_KEY;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    processor.TransTouchpadRightButton(data, evenType, button);
}

/**
 * @tc.name: MouseTransformProcessorTest_TransTouchpadRightButton_05
 * @tc.desc: Test TransTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_TransTouchpadRightButton_05, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    processor.TransTouchpadRightButton(data, evenType, button);
}

/**
 * @tc.name: MouseTransformProcessorTest_TransTouchpadRightButton_06
 * @tc.desc: Test TransTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_TransTouchpadRightButton_06, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    processor.SetTouchpadRightClickType(2);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    processor.TransTouchpadRightButton(data, evenType, button);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandlePostInner_01
 * @tc.desc: Test HandlePostInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandlePostInner_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    PointerEvent::PointerItem item;
    item.SetDisplayX(10);
    item.SetDisplayY(15);
    item.SetWindowX(0);
    item.SetWindowY(0);
    item.SetPointerId(1);
    item.SetPressed(true);
    item.SetDownTime(1000);
    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0.5);

    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 2);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    libinput_event_pointer* data = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(data != nullptr);
    libinput_pointer_axis_source source = libinput_event_pointer_get_axis_source(data);
    source = LIBINPUT_POINTER_AXIS_SOURCE_FINGER;

    bool ret = processor.HandlePostInner(data, item);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisInner_02
 * @tc.desc: Test HandleAxisInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisInner_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    bool isAxisBegin;
    MouseTransformProcessor processor(deviceId);

    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 2);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 2220);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 727);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 710);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto data = libinput_event_get_pointer_event(event);

    isAxisBegin = false;
    int32_t ret = processor.HandleAxisInner(data);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerSpeed_00
 * @tc.desc: Test the funcation SetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    int32_t speed = -1;
    ASSERT_EQ(processor.SetPointerSpeed(speed), 0);
    speed = 15;
    ASSERT_EQ(processor.SetPointerSpeed(speed), 0);
    speed = 5;
    EXPECT_NO_FATAL_FAILURE(processor.SetPointerSpeed(speed));
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisBeginEndInner_002
 * @tc.desc: Test the funcation HandleAxisBeginEndInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisBeginEndInner_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    processor.buttonId_ = PointerEvent::BUTTON_NONE;
    processor.isAxisBegin_ = false;
    processor.isPressed_ = true;
    int32_t ret = processor.HandleAxisBeginEndInner(event);
    EXPECT_EQ(ret, RET_ERR);
    processor.isAxisBegin_ = true;
    ret = processor.HandleAxisBeginEndInner(event);
    EXPECT_EQ(ret, RET_OK);
    processor.isPressed_ = false;
    ret = processor.HandleAxisBeginEndInner(event);
    EXPECT_EQ(ret, RET_ERR);
}
}
}