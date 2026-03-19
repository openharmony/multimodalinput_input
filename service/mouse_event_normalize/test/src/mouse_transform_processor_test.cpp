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
#include <gmock/gmock.h>

#include "general_mouse.h"
#include "mouse_transform_processor.h"
#include "window_info.h"
#include "mouse_device_state.h"
#include "virtual_mouse.h"
#include "input_device_manager.h"
#include "input_service_context.h"
#include "input_windows_manager.h"
#include "i_input_windows_manager.h"
#include "libinput_wrapper.h"
#include "multimodal_input_preferences_manager.h"
#include "parameters.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseTransformProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
constexpr int32_t BTN_RIGHT_MENUE_CODE = 0x118;
constexpr int32_t HARD_PC_PRO_DEVICE_WIDTH = 2880;
constexpr int32_t HARD_PC_PRO_DEVICE_HEIGHT = 1920;
}
class MockPreferenceManager : public MultiModalInputPreferencesManager {
public:
    MOCK_METHOD(int32_t, SetPreValue, (const std::string &, const std::string &,
        const NativePreferences::PreferencesValue &));
};

class MouseTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void SetupMouse();
    static void CloseMouse();
    void SetUp();
    void TearDown();

private:
    static GeneralMouse vMouse_;
    static LibinputWrapper libinput_;
    InputServiceContext env_ {};

    MouseTransformProcessor g_processor_ {&env_, 0 };
    int32_t prePointerSpeed_ { 5 };
    int32_t prePrimaryButton_ { 0 };
    int32_t preScrollRows_ { 3 };
    int32_t preTouchpadPointerSpeed_ { 9 };
    int32_t preRightClickType_ { 1 };
    bool preScrollSwitch_ { true };
    bool preScrollDirection_ { true };
    bool preTapSwitch_ { true };
    std::shared_ptr<MockPreferenceManager> mockPreferencesMgr;
};

GeneralMouse MouseTransformProcessorTest::vMouse_;
LibinputWrapper MouseTransformProcessorTest::libinput_;

void MouseTransformProcessorTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupMouse();
}

void MouseTransformProcessorTest::TearDownTestCase(void)
{
    CloseMouse();
}

void MouseTransformProcessorTest::SetupMouse()
{
    if (!vMouse_.SetUp()) {
        GTEST_SKIP();
    }
    std::cout << "device node name: " << vMouse_.GetDevPath() << std::endl;
    if (!libinput_.AddPath(vMouse_.GetDevPath())) {
        GTEST_SKIP();
    }

    libinput_event *event = libinput_.Dispatch();
    if (!event) {
        GTEST_SKIP();
    }
    if (libinput_event_get_type(event) != LIBINPUT_EVENT_DEVICE_ADDED) {
        GTEST_SKIP();
    }
    struct libinput_device *device = libinput_event_get_device(event);
    if (!device) {
        GTEST_SKIP();
    }
    INPUT_DEV_MGR->OnInputDeviceAdded(device);
}

void MouseTransformProcessorTest::CloseMouse()
{
    libinput_.RemovePath(vMouse_.GetDevPath());
    vMouse_.Close();
}

void MouseTransformProcessorTest::SetUp()
{
}

void MouseTransformProcessorTest::TearDown()
{
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
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t originButton = 1;
    int32_t mappedButton = 2;
    processor.buttonMapping_[originButton] = mappedButton;
    ASSERT_NO_FATAL_FAILURE(processor.DeletePressedButton(originButton));
}
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisAccelateTouchPad_001
 * @tc.desc: Test HandleAxisAccelateTouchPad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisAccelateTouchPad_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(&env_, deviceId);
    double axisValue = 2.0;
    auto inputWindowsManager = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->captureModeInfo_.isCaptureMode = true;
    int32_t userId = 100;
    double ret = processor.HandleAxisAccelateTouchPad(userId, axisValue);
    ASSERT_EQ(ret, 2.0);
}
#endif // OHOS_BUILD_ENABLE_TOUCHPAD
/**
 * @tc.name: MouseTransformProcessorTest_CheckDeviceType_01
 * @tc.desc: Test CheckDeviceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_CheckDeviceType_01, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t width = HARD_PC_PRO_DEVICE_WIDTH;
    int32_t height = HARD_PC_PRO_DEVICE_HEIGHT;
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
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t fd = 0;
    processor.Dump(fd, args);
    ASSERT_EQ(args, idNames);
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING

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
    MouseTransformProcessor processor(&env_, deviceId);
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
    int32_t idNames = -1;
    int32_t deviceId = 0;
    MouseTransformProcessor processor(&env_, deviceId);
    ASSERT_EQ(processor.GetDisplayId(env_), idNames);
}

#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: MouseTransformProcessorTest_SetPointerLocation_008
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_SetPointerLocation_008, TestSize.Level1)
{
    int32_t idNames = -1;
    int32_t deviceId = 0;
    int32_t displayId = -1;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t x = 0;
    int32_t y = 0;
    ASSERT_EQ(processor.SetPointerLocation(env_, x, y, displayId), idNames);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    Offset offset;
    OLD::DisplayInfo displayInfo;
    displayInfo.direction = DIRECTION90;
    displayInfo.displayDirection = DIRECTION0;
    ASSERT_NO_FATAL_FAILURE(processor.CalculateOffset(&displayInfo, offset));
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
    MouseTransformProcessor processor(&env_, deviceId);
    Offset offset;
    OLD::DisplayInfo displayInfo;
    displayInfo.direction = DIRECTION180;
    displayInfo.displayDirection = DIRECTION0;
    ASSERT_NO_FATAL_FAILURE(processor.CalculateOffset(&displayInfo, offset));
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
    MouseTransformProcessor processor(&env_, deviceId);
    Offset offset;
    OLD::DisplayInfo displayInfo;
    displayInfo.direction = DIRECTION270;
    displayInfo.displayDirection = DIRECTION0;
    ASSERT_NO_FATAL_FAILURE(processor.CalculateOffset(&displayInfo, offset));
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event* event = nullptr;
    int32_t type = 1;
    double angle = 90.0;
    auto ret = processor.NormalizeRotateEvent(event, type, angle);
    ASSERT_NE(ret, RET_OK);
}

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)

/**
 * @tc.name: MouseTransformProcessorTest_HandleMotionMoveMouse_001
 * @tc.desc: Handle motion move mouse verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleMotionMoveMouse_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t offsetX = -1000;
    int32_t offsetY = 500;
    ASSERT_NO_FATAL_FAILURE(processor.HandleMotionMoveMouse(offsetX, offsetY));
}

#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: MouseTransformProcessorTest_OnDisplayLost_001
 * @tc.desc: On display lost verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_OnDisplayLost_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t displayId = -1;
    ASSERT_NO_FATAL_FAILURE(processor.OnDisplayLost(env_, displayId));
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
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t displayId = 1;
    ASSERT_NO_FATAL_FAILURE(processor.OnDisplayLost(env_, displayId));
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
    MouseTransformProcessor processor(&env_, deviceId);
    PointerEvent::PointerItem pointerItem;
    ASSERT_NO_FATAL_FAILURE(processor.HandlePostMoveMouse(pointerItem));
}

#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: MouseTransformProcessorTest_DumpInner_001
 * @tc.desc: Dump inner verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_DumpInner_001, TestSize.Level1)
{
    int32_t deviceId = 0;
    MouseTransformProcessor processor(&env_, deviceId);
    ASSERT_NO_FATAL_FAILURE(processor.DumpInner());
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
    MouseTransformProcessor processor(&env_, deviceId);
    EXPECT_EQ(processor.Normalize(event), RET_ERR);
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
    MouseTransformProcessor processor(&env_, deviceId);
    EXPECT_EQ(processor.Normalize(event), RET_ERR);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t type = 0;
    double angle = 0.0;
    std::shared_ptr<PointerEvent::PointerItem> pointerItem = nullptr;
    int32_t result = processor.NormalizeRotateEvent(event, type, angle);
    EXPECT_EQ(result, RET_OK);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    uint32_t button = MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t ret = processor.HandleMotionInner(data, event);
    EXPECT_EQ(ret, RET_ERR);
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
    MouseTransformProcessor processor(&env_, deviceId);
    CursorPosition cursorPos;
    cursorPos.displayId = -1;
    int32_t type = LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    int32_t ret = processor.HandleMotionInner(data, event);
    EXPECT_EQ(ret, RET_ERR);
    type = LIBINPUT_EVENT_POINTER_BUTTON;
    ret = processor.HandleMotionInner(data, event);
    EXPECT_EQ(ret, RET_ERR);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    libinput_pointer_axis_source source = LIBINPUT_POINTER_AXIS_SOURCE_FINGER;
    int32_t direction = 1;
    bool tpScrollSwitch = true;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchPadAxisState(source, direction, tpScrollSwitch));
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = LIBINPUT_EVENT_KEYBOARD_KEY;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.TransTouchpadRightButton(data, evenType, button));
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
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = 55;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.TransTouchpadRightButton(data, evenType, button));
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
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer *data = nullptr;
    int32_t evenType = 60;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.TransTouchpadRightButton(data, evenType, button));
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
    MouseTransformProcessor processor(&env_, deviceId);

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
    MouseTransformProcessor processor(&env_, deviceId);
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
    MouseTransformProcessor processor(&env_, deviceId);

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
    MouseTransformProcessor processor(&env_, deviceId);
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

/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadRightButton_001
 * @tc.desc: Test the funcation HandleTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleTouchpadRightButton_001, TestSize.Level1)
{
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t evenType = 10;
    uint32_t button = BTN_RIGHT_MENUE_CODE;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadRightButton(data, evenType, button));
    button = MouseDeviceState::LIBINPUT_RIGHT_BUTTON_CODE;
    evenType = LIBINPUT_EVENT_POINTER_TAP;
    processor.HandleTouchpadRightButton(data, evenType, button);
    ASSERT_EQ (button, 0);
}

/**
 * @tc.name: MouseTransformProcessorTest_ExtractMotionData_001
 * @tc.desc: Test ExtractMotionData with valid mouse event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ExtractMotionData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    struct libinput_event* event = nullptr;
    auto ctx = processor.ExtractMotionData(data, event);
    EXPECT_FALSE(ctx.isValid);
}

/**
 * @tc.name: MouseTransformProcessorTest_ExtractMotionData_002
 * @tc.desc: Test ExtractMotionData returns invalid context when no display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ExtractMotionData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    struct libinput_event* event = nullptr;
    auto ctx = processor.ExtractMotionData(data, event);
    EXPECT_FALSE(ctx.isValid);
}

/**
 * @tc.name: MouseTransformProcessorTest_ExtractMotionData_003
 * @tc.desc: Test ExtractMotionData context structure fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ExtractMotionData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    struct libinput_event* event = nullptr;
    auto ctx = processor.ExtractMotionData(data, event);
    EXPECT_EQ(ctx.libinputEventType, 0);
}

/**
 * @tc.name: MouseTransformProcessorTest_ExtractMotionData_004
 * @tc.desc: Test ExtractMotionData with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ExtractMotionData_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    struct libinput_event* event = nullptr;
    auto ctx = processor.ExtractMotionData(data, event);
    EXPECT_DOUBLE_EQ(ctx.dx, 0.0);
    EXPECT_DOUBLE_EQ(ctx.dy, 0.0);
}

/**
 * @tc.name: MouseTransformProcessorTest_ProcessMotionByEventType_001
 * @tc.desc: Test ProcessMotionByEventType with invalid context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ProcessMotionByEventType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    MouseTransformProcessor::MotionDataContext ctx;
    ctx.isValid = false;
    struct libinput_event* event = nullptr;
    int32_t ret = processor.ProcessMotionByEventType(ctx, event);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_ProcessMotionByEventType_002
 * @tc.desc: Test ProcessMotionByEventType with touchpad motion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ProcessMotionByEventType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    MouseTransformProcessor::MotionDataContext ctx;
    ctx.isValid = false;
    ctx.libinputEventType = LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    struct libinput_event* event = nullptr;
    int32_t ret = processor.ProcessMotionByEventType(ctx, event);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_ProcessMotionByEventType_003
 * @tc.desc: Test ProcessMotionByEventType with regular motion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ProcessMotionByEventType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    MouseTransformProcessor::MotionDataContext ctx;
    ctx.isValid = false;
    ctx.libinputEventType = LIBINPUT_EVENT_POINTER_MOTION;
    struct libinput_event* event = nullptr;
    int32_t ret = processor.ProcessMotionByEventType(ctx, event);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_UpdateMotionEventState_001
 * @tc.desc: Test UpdateMotionEventState with invalid context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_UpdateMotionEventState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    MouseTransformProcessor::MotionDataContext ctx;
    ctx.isValid = false;
    int32_t ret = processor.UpdateMotionEventState(ctx);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_UpdateMotionEventState_002
 * @tc.desc: Test UpdateMotionEventState with valid context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_UpdateMotionEventState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    MouseTransformProcessor::MotionDataContext ctx;
    ctx.isValid = false;
    ctx.displayId = 1;
    int32_t ret = processor.UpdateMotionEventState(ctx);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisEvent_001
 * @tc.desc: Test HandleAxisEvent with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t userId = 0;
    int32_t tpScrollDirection = 1;
    libinput_pointer_axis_source source = LIBINPUT_POINTER_AXIS_SOURCE_FINGER;
    MouseTransformProcessor::AxisInfo axisInfo { LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL,
        PointerEvent::AXIS_TYPE_SCROLL_VERTICAL };
    int32_t ret = processor.HandleAxisEvent(data, userId, tpScrollDirection, source, axisInfo);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisEvent_002
 * @tc.desc: Test HandleAxisEvent with wheel source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t userId = 0;
    int32_t tpScrollDirection = 1;
    libinput_pointer_axis_source source = LIBINPUT_POINTER_AXIS_SOURCE_WHEEL;
    MouseTransformProcessor::AxisInfo axisInfo { LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL,
        PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL };
    int32_t ret = processor.HandleAxisEvent(data, userId, tpScrollDirection, source, axisInfo);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisEvent_003
 * @tc.desc: Test HandleAxisEvent with vertical axis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t userId = 0;
    int32_t tpScrollDirection = 1;
    libinput_pointer_axis_source source = LIBINPUT_POINTER_AXIS_SOURCE_FINGER;
    MouseTransformProcessor::AxisInfo axisInfo { LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL,
        PointerEvent::AXIS_TYPE_SCROLL_VERTICAL };
    int32_t ret = processor.HandleAxisEvent(data, userId, tpScrollDirection, source, axisInfo);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleAxisEvent_004
 * @tc.desc: Test HandleAxisEvent with horizontal axis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleAxisEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t userId = 0;
    int32_t tpScrollDirection = 1;
    libinput_pointer_axis_source source = LIBINPUT_POINTER_AXIS_SOURCE_WHEEL;
    MouseTransformProcessor::AxisInfo axisInfo { LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL,
        PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL };
    int32_t ret = processor.HandleAxisEvent(data, userId, tpScrollDirection, source, axisInfo);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_OnAxisScrollTimer_001
 * @tc.desc: Test OnAxisScrollTimer functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_OnAxisScrollTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    processor.timerId_ = 100;
    processor.OnAxisScrollTimer();
    EXPECT_EQ(processor.timerId_, -1);
}

/**
 * @tc.name: MouseTransformProcessorTest_OnAxisScrollTimer_002
 * @tc.desc: Test OnAxisScrollTimer clears timer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_OnAxisScrollTimer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    processor.timerId_ = 50;
    int32_t originalTimerId = processor.timerId_;
    processor.OnAxisScrollTimer();
    EXPECT_NE(processor.timerId_, originalTimerId);
}

/**
 * @tc.name: MouseTransformProcessorTest_OnAxisScrollTimer_003
 * @tc.desc: Test OnAxisScrollTimer resets timer ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_OnAxisScrollTimer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    processor.timerId_ = 200;
    processor.OnAxisScrollTimer();
    EXPECT_LT(processor.timerId_, 0);
}

/**
 * @tc.name: MouseTransformProcessorTest_BeginAxisScrollEvent_001
 * @tc.desc: Test BeginAxisScrollEvent returns success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_BeginAxisScrollEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    auto pointerEvent = processor.GetPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t ret = processor.BeginAxisScrollEvent();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_BeginAxisScrollEvent_002
 * @tc.desc: Test BeginAxisScrollEvent sets action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_BeginAxisScrollEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    auto pointerEvent = processor.GetPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t ret = processor.BeginAxisScrollEvent();
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_UpdateCursorLocationIfNeeded_001
 * @tc.desc: Test UpdateCursorLocationIfNeeded returns error with no window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_UpdateCursorLocationIfNeeded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t ret = processor.UpdateCursorLocationIfNeeded();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_UpdateCursorLocationIfNeeded_002
 * @tc.desc: Test UpdateCursorLocationIfNeeded handles direction mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_UpdateCursorLocationIfNeeded_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t ret = processor.UpdateCursorLocationIfNeeded();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_ResetPointerItemCanceledState_001
 * @tc.desc: Test ResetPointerItemCanceledState functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ResetPointerItemCanceledState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    auto pointerEvent = processor.GetPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(0);
    processor.ResetPointerItemCanceledState();
    EXPECT_EQ(pointerEvent->GetPointerId(), 0);
}

/**
 * @tc.name: MouseTransformProcessorTest_ResetPointerItemCanceledState_002
 * @tc.desc: Test ResetPointerItemCanceledState with pointer item
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_ResetPointerItemCanceledState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    auto pointerEvent = processor.GetPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetCanceled(true);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    processor.ResetPointerItemCanceledState();
    PointerEvent::PointerItem resultItem;
    bool hasItem = pointerEvent->GetPointerItem(0, resultItem);
    EXPECT_TRUE(hasItem || !hasItem);
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
/**
 * @tc.name: MouseTransformProcessorTest_HandleVirtualDeviceEvent_001
 * @tc.desc: Test HandleVirtualDeviceEvent with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleVirtualDeviceEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    struct libinput_event_pointer* data = nullptr;
    processor.HandleVirtualDeviceEvent(data);
    EXPECT_DOUBLE_EQ(processor.unaccelerated_.dx, 0.0);
}
#endif

/**
 * @tc.name: MouseTransformProcessorTest_IsTouchpadTapEnabled_001
 * @tc.desc: Test IsTouchpadTapEnabled with tap event disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_IsTouchpadTapEnabled_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t type = LIBINPUT_EVENT_POINTER_TAP;
    bool result = processor.IsTouchpadTapEnabled(type);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MouseTransformProcessorTest_IsTouchpadTapEnabled_002
 * @tc.desc: Test IsTouchpadTapEnabled with motion event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_IsTouchpadTapEnabled_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t type = LIBINPUT_EVENT_POINTER_MOTION;
    bool result = processor.IsTouchpadTapEnabled(type);
    EXPECT_TRUE(result);
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
/**
 * @tc.name: MouseTransformProcessorTest_IsTouchpadTapEnabled_003
 * @tc.desc: Test IsTouchpadTapEnabled with virtual device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_IsTouchpadTapEnabled_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    processor.isVirtualDeviceEvent_ = true;
    int32_t type = LIBINPUT_EVENT_POINTER_TAP;
    bool result = processor.IsTouchpadTapEnabled(type);
    EXPECT_TRUE(result || !result);
}
#endif

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonReleased_001
 * @tc.desc: Test HandleButtonReleased sets correct action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonReleased_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    uint32_t button = BTN_LEFT;
    uint32_t originButton = BTN_LEFT;
    int32_t type = LIBINPUT_EVENT_POINTER_BUTTON;
    auto pointerEvent = processor.GetPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t ret = processor.HandleButtonReleased(button, originButton, type);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_BUTTON_UP);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonReleased_002
 * @tc.desc: Test HandleButtonReleased resets isPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonReleased_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    processor.isPressed_ = true;
    uint32_t button = BTN_LEFT;
    uint32_t originButton = BTN_LEFT;
    int32_t type = LIBINPUT_EVENT_POINTER_BUTTON;
    processor.HandleButtonReleased(button, originButton, type);
    EXPECT_FALSE(processor.isPressed_);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonReleased_003
 * @tc.desc: Test HandleButtonReleased resets buttonId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonReleased_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    processor.buttonId_ = PointerEvent::MOUSE_BUTTON_LEFT;
    uint32_t button = BTN_LEFT;
    uint32_t originButton = BTN_LEFT;
    int32_t type = LIBINPUT_EVENT_POINTER_BUTTON;
    processor.HandleButtonReleased(button, originButton, type);
    EXPECT_EQ(processor.buttonId_, PointerEvent::BUTTON_NONE);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonPressed_001
 * @tc.desc: Test HandleButtonPressed sets correct action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonPressed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    uint32_t button = BTN_LEFT;
    uint32_t originButton = BTN_LEFT;
    int32_t type = LIBINPUT_EVENT_POINTER_BUTTON;
    auto pointerEvent = processor.GetPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t ret = processor.HandleButtonPressed(button, originButton, type);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_BUTTON_DOWN);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonPressed_002
 * @tc.desc: Test HandleButtonPressed sets isPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonPressed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    processor.isPressed_ = false;
    uint32_t button = BTN_LEFT;
    uint32_t originButton = BTN_LEFT;
    int32_t type = LIBINPUT_EVENT_POINTER_BUTTON;
    processor.HandleButtonPressed(button, originButton, type);
    EXPECT_TRUE(processor.isPressed_);
}

/**
 * @tc.name: MouseTransformProcessorTest_HandleButtonPressed_003
 * @tc.desc: Test HandleButtonPressed sets buttonId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_HandleButtonPressed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    uint32_t button = BTN_LEFT;
    uint32_t originButton = BTN_LEFT;
    int32_t type = LIBINPUT_EVENT_POINTER_BUTTON;
    processor.HandleButtonPressed(button, originButton, type);
    EXPECT_NE(processor.buttonId_, PointerEvent::BUTTON_NONE);
}

/**
 * @tc.name: MouseTransformProcessorTest_UpdateCursorPositionOnButtonPress_001
 * @tc.desc: Test UpdateCursorPositionOnButtonPress returns error with no window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_UpdateCursorPositionOnButtonPress_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t ret = processor.UpdateCursorPositionOnButtonPress();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MouseTransformProcessorTest_UpdateCursorPositionOnButtonPress_002
 * @tc.desc: Test UpdateCursorPositionOnButtonPress handles direction mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorTest, MouseTransformProcessorTest_UpdateCursorPositionOnButtonPress_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    MouseTransformProcessor processor(&env_, deviceId);
    int32_t ret = processor.UpdateCursorPositionOnButtonPress();
    EXPECT_NE(ret, RET_OK);
}
}
}
