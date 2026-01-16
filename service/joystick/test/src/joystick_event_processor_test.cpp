/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <filesystem>
#include <iomanip>
#include "linux/input.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "input_device_manager.h"
#include "input_service_context.h"
#include "joystick_event_processor.h"
#include "joystick_layout_map_builder.h"
#include "key_event_value_transformation.h"
#include "key_map_manager.h"
#include "libinput_mock.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
const std::string CONFIG_BASE_PATH { "/data/test/" };
char g_cfgName[] { "/data/test/TEST_DEVICE_NAME.json" };
char g_deviceName[] { "TEST_DEVICE_NAME" };
} // namespace

using namespace testing;
using namespace testing::ext;

class JoystickEventProcessorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    InputServiceContext env_ {};
};

void JoystickEventProcessorTest::SetUpTestCase()
{
    if (!std::filesystem::exists(CONFIG_BASE_PATH)) {
        std::error_code ec {};
        std::filesystem::create_directory(CONFIG_BASE_PATH, ec);
    }
    JoystickLayoutMap::AddConfigBasePath(CONFIG_BASE_PATH);
}

void JoystickEventProcessorTest::TearDownTestCase()
{}

void JoystickEventProcessorTest::SetUp()
{}

void JoystickEventProcessorTest::TearDown()
{
    std::filesystem::remove(g_cfgName);
    InputDeviceManagerMock::ReleaseInstance();
    KeyMapManager::ReleaseInstance();
}

/**
 * @tc.name: JoystickEventProcessorTest_OnButtonEvent_001
 * @tc.desc: Test OnButtonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnButtonEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device device {};
    struct libinput_event_joystick_button buttonEvent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&device));
    EXPECT_CALL(libinputMock, JoystickGetButtonEvent).WillRepeatedly(Return(&buttonEvent));
    EXPECT_CALL(libinputMock, JoystickButtonGetKey).WillRepeatedly(Return(BTN_A));
    EXPECT_CALL(libinputMock, JoystickButtonGetKeyState).WillRepeatedly(Return(LIBINPUT_BUTTON_STATE_RELEASED));
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*KeyMapMgr, TransferDefaultKeyValue).WillOnce(Return(KeyEvent::KEYCODE_BUTTON_A));

    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    libinput_event event {};
    auto keyEvent = joystick.OnButtonEvent(&event);
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        EXPECT_EQ(keyEvent->GetKeyCode(), KeyEvent::KEYCODE_BUTTON_A);
        EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_UP);
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_OnButtonEvent_002
 * @tc.desc: Test OnButtonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnButtonEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t rawCode { BTN_THUMBL };

    JoystickLayoutMap::Key keyInfo {
        .keyCode_ = KeyEvent::KEYCODE_BUTTON_THUMBL,
    };
    JoystickLayoutMap layoutMap { &env_, g_cfgName };
    layoutMap.keys_.emplace(rawCode, keyInfo);
    JoystickLayoutMapBuilder::BuildJoystickLayoutMap(layoutMap, g_cfgName);

    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    struct libinput_event_joystick_button buttonEvent {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(g_deviceName));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&rawDev));
    EXPECT_CALL(libinputMock, JoystickGetButtonEvent).WillRepeatedly(Return(&buttonEvent));
    EXPECT_CALL(libinputMock, JoystickButtonGetKey).WillRepeatedly(Return(BTN_THUMBL));
    EXPECT_CALL(libinputMock, JoystickButtonGetKeyState).WillRepeatedly(Return(LIBINPUT_BUTTON_STATE_PRESSED));
    EXPECT_CALL(*KeyMapMgr, TransferDefaultKeyValue).WillRepeatedly(Return(KeyEvent::KEYCODE_BUTTON_A));


    JoystickEventProcessor joystick(&env_, deviceId);
    libinput_event event {};
    auto keyEvent = joystick.OnButtonEvent(&event);
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        EXPECT_EQ(keyEvent->GetKeyCode(), KeyEvent::KEYCODE_BUTTON_THUMBL);
        EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_OnAxisEvent_001
 * @tc.desc: Test OnAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(g_deviceName));
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(65535)).WillRepeatedly(Return(0));
    struct libinput_event_joystick_axis axisEvent {};
    EXPECT_CALL(libinputMock, JoystickGetAxisEvent).WillRepeatedly(Return(&axisEvent));
    EXPECT_CALL(libinputMock, JoystickAxisValueIsChanged).WillOnce(Return(1)).WillRepeatedly(Return(0));
    struct libinput_event_joystick_axis_abs_info absInfo {
        .value = 13355,
    };
    EXPECT_CALL(libinputMock, JoystickAxisGetAbsInfo).WillRepeatedly(Return(&absInfo));

    JoystickEventProcessor joystick(&env_, deviceId);
    libinput_event event {};
    auto pointerEvent = joystick.OnAxisEvent(&event);
    EXPECT_NE(pointerEvent, nullptr);
    if (pointerEvent != nullptr) {
        EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        EXPECT_TRUE(pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_X));
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_OnAxisEvent_002
 * @tc.desc: Test OnAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnAxisEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t splitValue { 32768 };
    JoystickLayoutMap::AxisInfo axisInfo {
        .mode_ = JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT,
        .axis_ = PointerEvent::AXIS_TYPE_ABS_BRAKE,
        .highAxis_ = PointerEvent::AXIS_TYPE_ABS_GAS,
        .splitValue_ = splitValue,
    };
    JoystickLayoutMap layoutMap { &env_, g_cfgName };
    layoutMap.axes_.emplace(ABS_X, axisInfo);
    JoystickLayoutMapBuilder::BuildJoystickLayoutMap(layoutMap, g_cfgName);

    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(g_deviceName));
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(65535)).WillRepeatedly(Return(0));
    struct libinput_event_joystick_axis axisEvent {};
    EXPECT_CALL(libinputMock, JoystickGetAxisEvent).WillRepeatedly(Return(&axisEvent));
    EXPECT_CALL(libinputMock, JoystickAxisValueIsChanged).WillOnce(Return(true)).WillRepeatedly(Return(false));
    struct libinput_event_joystick_axis_abs_info absInfo {
        .value = 13355,
    };
    EXPECT_CALL(libinputMock, JoystickAxisGetAbsInfo).WillRepeatedly(Return(&absInfo));

    JoystickEventProcessor joystick(&env_, deviceId);
    libinput_event event {};
    auto pointerEvent = joystick.OnAxisEvent(&event);
    EXPECT_NE(pointerEvent, nullptr);
    if (pointerEvent != nullptr) {
        EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        EXPECT_FALSE(pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_X));
        EXPECT_TRUE(pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_BRAKE));
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_OnAxisEvent_003
 * @tc.desc: Test OnAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnAxisEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JoystickLayoutMap::AxisInfo axisInfo {
        .mode_ = JoystickLayoutMap::AxisMode::AXIS_MODE_INVERT,
        .axis_ = PointerEvent::AXIS_TYPE_ABS_BRAKE,
    };
    JoystickLayoutMap layoutMap { &env_, g_cfgName };
    layoutMap.axes_.emplace(ABS_X, axisInfo);
    JoystickLayoutMapBuilder::BuildJoystickLayoutMap(layoutMap, g_cfgName);

    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(g_deviceName));
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(65535)).WillRepeatedly(Return(0));
    struct libinput_event_joystick_axis axisEvent {};
    EXPECT_CALL(libinputMock, JoystickGetAxisEvent).WillRepeatedly(Return(&axisEvent));
    EXPECT_CALL(libinputMock, JoystickAxisValueIsChanged).WillOnce(Return(1)).WillRepeatedly(Return(0));
    struct libinput_event_joystick_axis_abs_info absInfo {
        .value = 13355,
    };
    EXPECT_CALL(libinputMock, JoystickAxisGetAbsInfo).WillRepeatedly(Return(&absInfo));

    JoystickEventProcessor joystick(&env_, deviceId);
    libinput_event event {};
    auto pointerEvent = joystick.OnAxisEvent(&event);
    EXPECT_NE(pointerEvent, nullptr);
    if (pointerEvent != nullptr) {
        EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        EXPECT_FALSE(pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_X));
        EXPECT_TRUE(pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_BRAKE));
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_OnAxisEvent_004
 * @tc.desc: Test OnAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnAxisEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JoystickLayoutMap::AxisInfo axisInfo {
        .mode_ = JoystickLayoutMap::AxisMode::AXIS_MODE_INVERT,
        .axis_ = PointerEvent::AXIS_TYPE_ABS_BRAKE,
    };
    JoystickLayoutMap layoutMap { &env_, g_cfgName };
    layoutMap.axes_.emplace(ABS_X, axisInfo);
    JoystickLayoutMapBuilder::BuildJoystickLayoutMap(layoutMap, g_cfgName);

    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(g_deviceName));
    EXPECT_CALL(libinputMock, DeviceGetAxisMin).WillRepeatedly(Return(0));
    EXPECT_CALL(libinputMock, DeviceGetAxisMax).WillOnce(Return(65535)).WillRepeatedly(Return(0));
    struct libinput_event_joystick_axis axisEvent {};
    EXPECT_CALL(libinputMock, JoystickGetAxisEvent).WillRepeatedly(Return(&axisEvent));
    EXPECT_CALL(libinputMock, JoystickAxisValueIsChanged).WillRepeatedly(Return(true));
    EXPECT_CALL(libinputMock, JoystickAxisGetAbsInfo).WillRepeatedly(Return(nullptr));

    JoystickEventProcessor joystick(&env_, deviceId);
    libinput_event event {};
    auto pointerEvent = joystick.OnAxisEvent(&event);
    EXPECT_EQ(pointerEvent, nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention
 * @tc.desc: Test CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    std::shared_ptr<PointerEvent> pointerEvent;
    ASSERT_NO_FATAL_FAILURE(
        joystick.CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_002
 * @tc.desc: Test CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_LEFT};
    ASSERT_NO_FATAL_FAILURE(
        JoystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_003
 * @tc.desc: Test CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_DOWN};
    ASSERT_NO_FATAL_FAILURE(
        JoystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_004
 * @tc.desc: Test CheckIntention with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(
        joystickEvent->CheckIntention(pointerEvent, nullptr));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_005
 * @tc.desc: Test CheckIntention with non-joystick source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(
        joystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(joystick.CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_002
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_SCROLL_VERTICAL;
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_003
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
    axisValue = -0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_004
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_LEFT};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_RIGHT};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_005
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_006
 * @tc.desc: Test CheckHAT0X with positive axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_007
 * @tc.desc: Test CheckHAT0X with negative axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = -1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(joystick.CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_002
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_SCROLL_VERTICAL;
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_003
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
    axisValue = -0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_004
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_DOWN};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_UP};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_005
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_006
 * @tc.desc: Test CheckHAT0Y with positive axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_007
 * @tc.desc: Test CheckHAT0Y with negative axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = -1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_UpdateButtonState
 * @tc.desc: Test UpdateButtonState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_UpdateButtonState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    KeyEvent::KeyItem keyItem {};
    ASSERT_NO_FATAL_FAILURE(joystick.UpdateButtonState(keyItem));
}

/**
 * @tc.name: JoystickEventProcessorTest_UpdateButtonState_002
 * @tc.desc: Test UpdateButtonState with pressed button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_UpdateButtonState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(true);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    ASSERT_NO_FATAL_FAILURE(joystickEvent->UpdateButtonState(keyItem));
}

/**
 * @tc.name: JoystickEventProcessorTest_UpdateButtonState_003
 * @tc.desc: Test UpdateButtonState with released button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_UpdateButtonState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(false);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    KeyEvent::KeyItem pressedKey {};
    pressedKey.SetPressed(true);
    pressedKey.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);
    joystickEvent->UpdateButtonState(pressedKey);

    ASSERT_NO_FATAL_FAILURE(joystickEvent->UpdateButtonState(keyItem));
}

/**
 * @tc.name: JoystickEventProcessorTest_FormatButtonEvent
 * @tc.desc: Test FormatButtonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_FormatButtonEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    KeyEvent::KeyItem keyItem {};
    EXPECT_NE(joystick.FormatButtonEvent(keyItem), nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_FormatButtonEvent_002
 * @tc.desc: Test FormatButtonEvent with pressed button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_FormatButtonEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(true);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    auto keyEvent = joystickEvent->FormatButtonEvent(keyItem);
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_FormatButtonEvent_003
 * @tc.desc: Test FormatButtonEvent with released button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_FormatButtonEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(false);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    auto keyEvent = joystickEvent->FormatButtonEvent(keyItem);
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_UP);
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_CleanUpKeyEvent
 * @tc.desc: Test CleanUpKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CleanUpKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    EXPECT_NE(joystick.CleanUpKeyEvent(), nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_DumpJoystickAxisEvent
 * @tc.desc: Test DumpJoystickAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CleanUpKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);

    KeyEvent::KeyItem item1 {};
    item1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    item1.SetPressed(true);
    keyEvent->AddKeyItem(item1);

    KeyEvent::KeyItem item2 {};
    item2.SetKeyCode(KeyEvent::KEYCODE_A);
    item2.SetPressed(false);
    keyEvent->AddKeyItem(item2);

    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    joystick.keyEvent_ = keyEvent;
    auto event = joystick.CleanUpKeyEvent();
    EXPECT_EQ(event, keyEvent);
    if (event != nullptr) {
        auto optItem1 = event->GetKeyItem(KeyEvent::KEYCODE_CTRL_LEFT);
        EXPECT_TRUE(optItem1.has_value());
        if (optItem1) {
            EXPECT_EQ(optItem1->GetKeyCode(), KeyEvent::KEYCODE_CTRL_LEFT);
            EXPECT_TRUE(optItem1->IsPressed());
        }
        auto optItem2 = event->GetKeyItem(KeyEvent::KEYCODE_A);
        EXPECT_FALSE(optItem2.has_value());
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_DumpJoystickAxisEvent_003
 * @tc.desc: Test DumpJoystickAxisEvent with multiple axes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_DumpJoystickAxisEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(&env_, 2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X | PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = 0.5;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = -0.3;

    std::string dumpResult = joystickEvent->DumpJoystickAxisEvent(pointerEvent);
    ASSERT_NE(dumpResult, "");
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_DumpJoystickAxisEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(&env_, deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(joystick.DumpJoystickAxisEvent(pointerEvent), "");
}
} // namespace MMI
} // namespace OHOS
