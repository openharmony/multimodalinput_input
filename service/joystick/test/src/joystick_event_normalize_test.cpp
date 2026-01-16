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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "define_multimodal.h"
#include "input_device_manager.h"
#include "input_service_context.h"
#include "joystick_event_normalize.h"
#include "libinput_mock.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventNormalizeTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class JoystickEventNormalizeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    InputServiceContext env_ {};
};

void JoystickEventNormalizeTest::SetUpTestCase()
{}

void JoystickEventNormalizeTest::TearDownTestCase()
{}

void JoystickEventNormalizeTest::SetUp()
{}

void JoystickEventNormalizeTest::TearDown()
{
    InputDeviceManagerMock::ReleaseInstance();
}

/**
 * @tc.name: InputDeviceObserver_OnDeviceAdded_001
 * @tc.desc: Test JoystickEventNormalize::InputDeviceObserver::OnDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, InputDeviceObserver_OnDeviceAdded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));

    auto joystick = std::make_shared<JoystickEventNormalize>(&env_);
    joystick->OnDeviceAdded(deviceId);

    const auto &processors = joystick->processors_;
    auto iter = processors.find(&rawDev);
    EXPECT_NE(iter, processors.cend());
    if (iter != processors.cend()) {
        auto processor = iter->second;
        EXPECT_NE(processor, nullptr);
        if (processor != nullptr) {
            EXPECT_EQ(processor->GetDeviceId(), deviceId);
        }
    }
}

/**
 * @tc.name: JoystickEventNormalizeTest_OnDeviceRemoved_001
 * @tc.desc: Test JoystickEventNormalize::InputDeviceObserver::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, InputDeviceObserver_OnDeviceRemoved_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));
    int32_t deviceId { 2 };
    struct libinput_device rawDev {};
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(&rawDev));

    auto joystick = std::make_shared<JoystickEventNormalize>(&env_);
    joystick->OnDeviceAdded(deviceId);
    joystick->OnDeviceRemoved(deviceId);

    const auto &processors = joystick->processors_;
    EXPECT_EQ(processors.find(&rawDev), processors.cend());
}

/**
 * @tc.name: JoystickEventNormalizeTest_CheckIntention
 * @tc.desc: Test JoystickEventNormalize::CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_CheckIntention, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));

    auto joystick = std::make_shared<JoystickEventNormalize>(&env_);
    joystick->GetProcessor(&rawDev);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    double axisValue { 1.0 };
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X, axisValue);

    int32_t keyCode { KeyEvent::KEYCODE_UNKNOWN };
    int32_t keyAction { KeyEvent::KEY_ACTION_UNKNOWN };

    joystick->CheckIntention(pointerEvent, [&](std::shared_ptr<KeyEvent> keyEvent) {
        if (keyEvent != nullptr) {
            keyCode = keyEvent->GetKeyCode();
            keyAction = keyEvent->GetKeyAction();
        }
    });
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_DPAD_RIGHT);
    EXPECT_EQ(keyAction, KeyEvent::KEY_ACTION_DOWN);
}

/**
 * @tc.name: JoystickEventNormalizeTest_OnDeviceAdded_001
 * @tc.desc: Test JoystickEventNormalize::OnDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_OnDeviceAdded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillRepeatedly(Return(&rawDev));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));

    auto joystick = std::make_shared<JoystickEventNormalize>(&env_);
    joystick->OnDeviceAdded(deviceId);
    joystick->OnDeviceAdded(deviceId);

    const auto &processors = joystick->processors_;
    auto iter = processors.find(&rawDev);
    EXPECT_NE(iter, processors.cend());
    if (iter != processors.cend()) {
        auto processor = iter->second;
        EXPECT_NE(processor, nullptr);
        if (processor != nullptr) {
            EXPECT_EQ(processor->GetDeviceId(), deviceId);
        }
    }
}

/**
 * @tc.name: JoystickEventNormalizeTest_OnDeviceAdded_002
 * @tc.desc: Test JoystickEventNormalize::OnDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_OnDeviceAdded_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystick = std::make_shared<JoystickEventNormalize>(&env_);
    int32_t deviceId { 2 };
    joystick->OnDeviceAdded(deviceId);
    EXPECT_TRUE(joystick->processors_.empty());
}

/**
 * @tc.name: JoystickEventNormalizeTest_OnDeviceRemoved_001
 * @tc.desc: Test JoystickEventNormalize::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_OnDeviceRemoved_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    int32_t deviceId { 2 };
    libinput_device rawDev {};
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(&rawDev));

    auto joystick = std::make_shared<JoystickEventNormalize>(&env_);
    joystick->OnDeviceAdded(deviceId);
    joystick->OnDeviceRemoved(deviceId);

    const auto &processors =joystick->processors_;
    EXPECT_EQ(processors.find(&rawDev), processors.cend());
}

/**
 * @tc.name: JoystickEventNormalizeTest_FindProcessor
 * @tc.desc: Test FindProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_FindProcessor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventNormalize>(&env_);
    int32_t deviceId = 2;
    ASSERT_EQ(joystickEvent->FindProcessor(deviceId), nullptr);
}
} // namespace MMI
} // namespace OHOS
