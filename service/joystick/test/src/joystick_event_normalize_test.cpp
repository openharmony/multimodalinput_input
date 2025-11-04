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
};

void JoystickEventNormalizeTest::SetUpTestCase()
{}

void JoystickEventNormalizeTest::TearDownTestCase()
{
    InputDeviceManagerMock::ReleaseInstance();
}

void JoystickEventNormalizeTest::SetUp()
{
    JoystickEventNormalize::GetInstance()->inputDevObserver_ = nullptr;
    JoystickEventNormalize::GetInstance()->processors_.clear();
}

void JoystickEventNormalizeTest::TearDown()
{}

/**
 * @tc.name: InputDeviceObserver_OnDeviceAdded_001
 * @tc.desc: Test JoystickEventNormalize::InputDeviceObserver::OnDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, InputDeviceObserver_OnDeviceAdded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));
    int32_t deviceId { 2 };
    libinput_device rawDev {};
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(&rawDev));

    JoystickEventNormalize::InputDeviceObserver devObserver(JoystickEventNormalize::GetInstance());
    devObserver.OnDeviceAdded(deviceId);

    const auto &processors = JoystickEventNormalize::GetInstance()->processors_;
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
    libinput_device rawDev {};
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(&rawDev));

    JoystickEventNormalize::InputDeviceObserver devObserver(JoystickEventNormalize::GetInstance());
    devObserver.OnDeviceAdded(deviceId);
    devObserver.OnDeviceRemoved(deviceId);

    const auto &processors = JoystickEventNormalize::GetInstance()->processors_;
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
    int32_t deviceId { 1 };
    EXPECT_CALL(*INPUT_DEV_MGR, FindInputDeviceId).WillRepeatedly(Return(deviceId));
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(nullptr));

    struct libinput_device inputDev {};
    JoystickEventNormalize::GetInstance()->GetProcessor(&inputDev);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    double axisValue { 1.0 };
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X, axisValue);

    int32_t keyCode { KeyEvent::KEYCODE_UNKNOWN };
    int32_t keyAction { KeyEvent::KEY_ACTION_UNKNOWN };

    JOYSTICK_NORMALIZER->CheckIntention(pointerEvent, [&](std::shared_ptr<KeyEvent> keyEvent) {
        if (keyEvent != nullptr) {
            keyCode = keyEvent->GetKeyCode();
            keyAction = keyEvent->GetKeyAction();
        }
    });
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_DPAD_RIGHT);
    EXPECT_EQ(keyAction, KeyEvent::KEY_ACTION_DOWN);
}

/**
 * @tc.name: JoystickEventNormalizeTest_SetUpDeviceObserver_001
 * @tc.desc: Test JoystickEventNormalize::SetUpDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_SetUpDeviceObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(Exactly(1));

    JoystickEventNormalize::GetInstance()->SetUpDeviceObserver(JoystickEventNormalize::GetInstance());
    EXPECT_NE(JoystickEventNormalize::GetInstance()->inputDevObserver_, nullptr);
    JoystickEventNormalize::GetInstance()->TearDownDeviceObserver();
    EXPECT_EQ(JoystickEventNormalize::GetInstance()->inputDevObserver_, nullptr);
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
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));
    int32_t deviceId { 2 };
    libinput_device rawDev {};
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(&rawDev));

    JoystickEventNormalize::GetInstance()->OnDeviceAdded(deviceId);
    JoystickEventNormalize::GetInstance()->OnDeviceAdded(deviceId);

    const auto &processors = JoystickEventNormalize::GetInstance()->processors_;
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
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(nullptr));

    int32_t deviceId { 2 };
    JoystickEventNormalize::GetInstance()->OnDeviceAdded(deviceId);
    EXPECT_TRUE(JoystickEventNormalize::GetInstance()->processors_.empty());
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
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));
    int32_t deviceId { 2 };
    libinput_device rawDev {};
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(&rawDev));

    JoystickEventNormalize::GetInstance()->OnDeviceAdded(deviceId);
    JoystickEventNormalize::GetInstance()->OnDeviceRemoved(deviceId);

    const auto &processors = JoystickEventNormalize::GetInstance()->processors_;
    EXPECT_EQ(processors.find(&rawDev), processors.cend());
}

/**
 * @tc.name: JoystickEventNormalizeTest_GetProcessor
 * @tc.desc: Test GetProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_GetProcessor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    EXPECT_CALL(*INPUT_DEV_MGR, FindInputDeviceId).WillRepeatedly(Return(deviceId));
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(nullptr));

    libinput_device libDev;
    auto processor = JoystickEventNormalize::GetInstance()->GetProcessor(&libDev);
    ASSERT_NE(processor, nullptr);
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
    auto joystickEvent = std::make_shared<JoystickEventNormalize>();
    int32_t deviceId = 2;
    ASSERT_EQ(joystickEvent->FindProcessor(deviceId), nullptr);
}

/**
 * @tc.name: JoystickEventNormalizeTest_FindProcessor_002
 * @tc.desc: Test FindProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_FindProcessor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, GetLibinputDevice).WillRepeatedly(Return(nullptr));

    auto joystickEvent = std::make_shared<JoystickEventNormalize>();
    int32_t deviceId = 2;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    auto joystickEventProcessor = std::make_shared<JoystickEventProcessor>(deviceId);
    joystickEvent->processors_.insert(std::make_pair(&libDev, joystickEventProcessor));
    ASSERT_EQ(joystickEvent->FindProcessor(deviceId), joystickEventProcessor);
}
} // namespace MMI
} // namespace OHOS
