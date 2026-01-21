/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "ffrt.h"
#include "input_device_manager.h"
#include "input_service_context.h"
#include "joystick_event_interface.h"
#include "joystick_event_normalize.h"
#include "libinput_mock.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventInterfaceTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class JoystickEventInterfaceTest : public testing::Test {
public:
    JoystickEventInterfaceTest();

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    std::shared_ptr<InputServiceContext> env_ {};
};

JoystickEventInterfaceTest::JoystickEventInterfaceTest()
{
    env_ = std::make_shared<InputServiceContext>();
}

void JoystickEventInterfaceTest::SetUpTestCase()
{}

void JoystickEventInterfaceTest::TearDownTestCase()
{}

void JoystickEventInterfaceTest::SetUp()
{}

void JoystickEventInterfaceTest::TearDown()
{
    InputDeviceManagerMock::ReleaseInstance();
}

/**
 * @tc.name: OnButtonEvent_001
 * @tc.desc: Test JoystickEventInterface::OnButtonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnButtonEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    auto keyEvent = joystick->OnButtonEvent(nullptr);
    EXPECT_TRUE(keyEvent == nullptr);
}

/**
 * @tc.name: OnButtonEvent_002
 * @tc.desc: Test JoystickEventInterface::OnButtonEvent with valid button event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnButtonEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    // Create a mock button event
    NiceMock<LibinputEventMock> mockEvent;
    EXPECT_CALL(mockEvent, GetType).WillOnce(Return(LIBINPUT_EVENT_JOYSTICK_BUTTON));
    
    auto keyEvent = joystick->OnButtonEvent(&mockEvent);
    EXPECT_TRUE(keyEvent != nullptr);
}

/**
 * @tc.name: OnAxisEvent_001
 * @tc.desc: Test JoystickEventInterface::OnAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    auto event = joystick->OnAxisEvent(nullptr);
    EXPECT_TRUE(event == nullptr);
}

/**
 * @tc.name: OnAxisEvent_002
 * @tc.desc: Test JoystickEventInterface::OnAxisEvent with valid axis event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnAxisEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    // Create a mock axis event
    NiceMock<LibinputEventMock> mockEvent;
    EXPECT_CALL(mockEvent, GetType).WillOnce(Return(LIBINPUT_EVENT_JOYSTICK_AXIS));
    
    auto event = joystick->OnAxisEvent(&mockEvent);
    EXPECT_TRUE(event != nullptr);
}

/**
 * @tc.name: CheckIntention_001
 * @tc.desc: Test JoystickEventInterface::CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, CheckIntention_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

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
 * @tc.name: CheckIntention_002
 * @tc.desc: Test JoystickEventInterface::CheckIntention with different axis types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, CheckIntention_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    double axisValue { -1.0 };  // Negative value for left direction
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X, axisValue);

    int32_t keyCode { KeyEvent::KEYCODE_UNKNOWN };
    int32_t keyAction { KeyEvent::KEY_ACTION_UNKNOWN };

    joystick->CheckIntention(pointerEvent, [&](std::shared_ptr<KeyEvent> keyEvent) {
        if (keyEvent != nullptr) {
            keyCode = keyEvent->GetKeyCode();
            keyAction = keyEvent->GetKeyAction();
        }
    });
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_DPAD_LEFT);
    EXPECT_EQ(keyAction, KeyEvent::KEY_ACTION_DOWN);
}

/**
 * @tc.name: CheckIntention_003
 * @tc.desc: Test JoystickEventInterface::CheckIntention with Y-axis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, CheckIntention_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    double axisValueY { 1.0 };  // Positive Y for down direction
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0Y, axisValueY);

    int32_t keyCodeY { KeyEvent::KEYCODE_UNKNOWN };
    int32_t keyActionY { KeyEvent::KEY_ACTION_UNKNOWN };

    joystick->CheckIntention(pointerEvent, [&](std::shared_ptr<KeyEvent> keyEvent) {
        if (keyEvent != nullptr) {
            keyCodeY = keyEvent->GetKeyCode();
            keyActionY = keyEvent->GetKeyAction();
        }
    });
    EXPECT_EQ(keyCodeY, KeyEvent::KEYCODE_DPAD_DOWN);
    EXPECT_EQ(keyActionY, KeyEvent::KEY_ACTION_DOWN);
}

/**
 * @tc.name: CheckIntention_004
 * @tc.desc: Test JoystickEventInterface::CheckIntention with zero axis value (no intention)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, CheckIntention_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    double axisValue { 0.0 };  // Zero value should not trigger any intention
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X, axisValue);

    bool callbackCalled { false };

    joystick->CheckIntention(pointerEvent, [&](std::shared_ptr<KeyEvent> keyEvent) {
        callbackCalled = true;
    });
    EXPECT_FALSE(callbackCalled);  // Callback should not be called for zero value
}

/**
 * @tc.name: CheckIntention_005
 * @tc.desc: Test JoystickEventInterface::CheckIntention with invalid source type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, CheckIntention_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);  // Different source type
    
    double axisValue { 1.0 };
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X, axisValue);

    bool callbackCalled { false };

    joystick->CheckIntention(pointerEvent, [&](std::shared_ptr<KeyEvent> keyEvent) {
        callbackCalled = true;
    });
    EXPECT_FALSE(callbackCalled);  // Callback should not be called for wrong source type
}

/**
 * @tc.name: GetJoystick_001
 * @tc.desc: Test JoystickEventInterface::GetJoystick method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, GetJoystick_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    auto retrievedJoystick = joystick->GetJoystick();
    EXPECT_TRUE(retrievedJoystick != nullptr);
}

/**
 * @tc.name: GetJoystick_002
 * @tc.desc: Test JoystickEventInterface::GetJoystick when no joystick exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, GetJoystick_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);

    auto retrievedJoystick = joystick->GetJoystick();
    EXPECT_TRUE(retrievedJoystick == nullptr);
}

/**
 * @tc.name: SetUpDeviceObserver_001
 * @tc.desc: Test JoystickEventInterface::SetUpDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, SetUpDeviceObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(Exactly(1));
    JOYSTICK_NORMALIZER->SetUpDeviceObserver(JOYSTICK_NORMALIZER);
    EXPECT_TRUE(JOYSTICK_NORMALIZER->inputDevObserver_ != nullptr);
}

/**
 * @tc.name: OnDeviceAdded_001
 * @tc.desc: Test JoystickEventInterface::OnDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnDeviceAdded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    auto observer = std::make_shared<JoystickEventInterface::InputDeviceObserver>(joystick);
    observer->OnDeviceAdded(deviceId);
    ffrt::wait();

    EXPECT_TRUE(joystick->joystick_ != nullptr);
    if (joystick->joystick_ != nullptr) {
        EXPECT_TRUE(joystick->joystick_->HasJoystick());
    }
}

/**
 * @tc.name: OnDeviceAdded_002
 * @tc.desc: Test JoystickEventInterface::OnDeviceAdded when device is not a joystick
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnDeviceAdded_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(false));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    joystick->OnDeviceAdded(joystick, deviceId);
    ffrt::wait();

    EXPECT_TRUE(joystick->joystick_ == nullptr);
}

/**
 * @tc.name: OnDeviceRemoved_001
 * @tc.desc: Test JoystickEventInterface::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnDeviceRemoved_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    auto observer = std::make_shared<JoystickEventInterface::InputDeviceObserver>(joystick);
    observer->OnDeviceAdded(deviceId);
    ffrt::wait();
    observer->OnDeviceRemoved(deviceId);

    EXPECT_TRUE(joystick->joystick_ != nullptr);
    if (joystick->joystick_ != nullptr) {
        EXPECT_FALSE(joystick->joystick_->HasJoystick());
    }
    EXPECT_GE(joystick->unloadTimerId_, 0);
    TimerMgr->RemoveTimer(joystick->unloadTimerId_);
}

/**
 * @tc.name: OnDeviceRemoved_002
 * @tc.desc: Test JoystickEventInterface::OnDeviceRemoved with multiple devices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, OnDeviceRemoved_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId1 { 2 };
    int32_t deviceId2 { 3 };
    auto inputDev1 = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    auto inputDev2 = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev1, IsJoystick).WillRepeatedly(Return(true));
    EXPECT_CALL(*inputDev2, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev1 {}, rawDev2 {};
    EXPECT_CALL(*inputDev1, GetRawDevice).WillOnce(Return(&rawDev1)).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*inputDev2, GetRawDevice).WillOnce(Return(&rawDev2)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId1, inputDev1);
    INPUT_DEV_MGR->AddInputDevice(deviceId2, inputDev2);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    auto observer = std::make_shared<JoystickEventInterface::InputDeviceObserver>(joystick);
    
    // Add both devices
    observer->OnDeviceAdded(deviceId1);
    observer->OnDeviceAdded(deviceId2);
    ffrt::wait();
    
    // Remove one device
    observer->OnDeviceRemoved(deviceId1);
    ffrt::wait();

    // Joystick should still exist since another device is still connected
    EXPECT_TRUE(joystick->joystick_ != nullptr);
    if (joystick->joystick_ != nullptr) {
        EXPECT_TRUE(joystick->joystick_->HasJoystick());
    }

    // Remove second device
    observer->OnDeviceRemoved(deviceId2);
    ffrt::wait();

    // Now joystick should not exist anymore
    EXPECT_TRUE(joystick->joystick_ != nullptr);
    if (joystick->joystick_ != nullptr) {
        EXPECT_FALSE(joystick->joystick_->HasJoystick());
    }
    EXPECT_GE(joystick->unloadTimerId_, 0);
    TimerMgr->RemoveTimer(joystick->unloadTimerId_);
}

/**
 * @tc.name: UnloadJoystick_001
 * @tc.desc: Test JoystickEventInterface::UnloadJoystick
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventInterfaceTest, UnloadJoystick_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    auto inputDev = std::make_shared<NiceMock<InputDeviceManagerMock::HiddenInputDevice>>();
    EXPECT_CALL(*inputDev, IsJoystick).WillRepeatedly(Return(true));
    struct libinput_device rawDev {};
    EXPECT_CALL(*inputDev, GetRawDevice).WillOnce(Return(&rawDev)).WillRepeatedly(Return(nullptr));
    INPUT_DEV_MGR->AddInputDevice(deviceId, inputDev);

    auto joystick = std::make_shared<JoystickEventInterface>();
    joystick->AttachInputServiceContext(env_);
    auto observer = std::make_shared<JoystickEventInterface::InputDeviceObserver>(joystick);
    observer->OnDeviceAdded(deviceId);
    ffrt::wait();

    joystick->UnloadJoystick();
    EXPECT_EQ(joystick->unloadTimerId_, -1);
    EXPECT_EQ(joystick->joystick_, nullptr);
}
} // namespace MMI
} // namespace OHOS
