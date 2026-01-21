/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "input_device_manager.h"
#include "key_auto_repeat.h"
#include "key_map_manager.h"
#include "libinput_mock.h"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class InputDeviceManagerTestWithMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void InputDeviceManagerTestWithMock::SetUpTestCase()
{}

void InputDeviceManagerTestWithMock::TearDownTestCase()
{
    KeyMapManager::ReleaseInstance();
    KeyAutoRepeat::ReleaseInstance();
}

class InputDeviceObserver : public IDeviceObserver {
public:
    MOCK_METHOD(void, OnDeviceAdded, (int32_t));
    MOCK_METHOD(void, OnDeviceRemoved, (int32_t));
    MOCK_METHOD(void, UpdatePointerDevice, (bool, bool, bool));
};

/**
 * @tc.name: HiddenInputDevice_GetRawDevice_001
 * @tc.desc: Test the function HiddenInputDevice::GetRawDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, HiddenInputDevice_GetRawDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
    };
    InputDeviceManager::HiddenInputDevice inputDev { devInfo };
    EXPECT_EQ(inputDev.GetRawDevice(), &rawDev);
}

/**
 * @tc.name: HiddenInputDevice_GetName_001
 * @tc.desc: Test the function HiddenInputDevice::GetName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, HiddenInputDevice_GetName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char devName[] { "D1" };
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(devName));

    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
    };
    InputDeviceManager::HiddenInputDevice inputDev { devInfo };
    EXPECT_EQ(inputDev.GetName(), std::string(devName));
}

/**
 * @tc.name: HiddenInputDevice_GetName_002
 * @tc.desc: Test the function HiddenInputDevice::GetName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, HiddenInputDevice_GetName_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo devInfo {};
    InputDeviceManager::HiddenInputDevice inputDev { devInfo };
    EXPECT_EQ(inputDev.GetName(), std::string("null"));
}

/**
 * @tc.name: InputDeviceManager_001
 * @tc.desc: Test the function InputDeviceManager::InputDeviceManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, InputDeviceManager_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(INPUT_DEV_MGR->observers_.empty());
}

/**
 * @tc.name: CheckDevice_001
 * @tc.desc: Test the function InputDeviceManager::CheckDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, CheckDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    int32_t deviceId { 888 };
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
    };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);
    auto isJoystick = INPUT_DEV_MGR->CheckDevice(deviceId,
        [](const IInputDeviceManager::IInputDevice &dev) {
            return dev.IsJoystick();
        });
    EXPECT_TRUE(isJoystick);
}

/**
 * @tc.name: CheckDevice_002
 * @tc.desc: Test the function InputDeviceManager::CheckDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, CheckDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 888 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);
    auto isJoystick = INPUT_DEV_MGR->CheckDevice(deviceId,
        [](const IInputDeviceManager::IInputDevice &dev) {
            return dev.IsJoystick();
        });
    EXPECT_FALSE(isJoystick);
}

/**
 * @tc.name: CheckDevice_003
 * @tc.desc: Test the function InputDeviceManager::CheckDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, CheckDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 888 };
    auto isJoystick = INPUT_DEV_MGR->CheckDevice(deviceId,
        [](const IInputDeviceManager::IInputDevice &dev) {
            return dev.IsJoystick();
        });
    EXPECT_FALSE(isJoystick);
}

/**
 * @tc.name: CheckDevice_004
 * @tc.desc: Test the function InputDeviceManager::CheckDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, CheckDevice_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 888 };
    auto isJoystick = INPUT_DEV_MGR->CheckDevice(deviceId, nullptr);
    EXPECT_FALSE(isJoystick);
}

/**
 * @tc.name: ForEachDevice_001
 * @tc.desc: Test the function InputDeviceManager::ForEachDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, ForEachDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    int32_t deviceId { 888 };
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
    };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    bool isJoystick { false };
    INPUT_DEV_MGR->ForEachDevice(
        [deviceId, &isJoystick](int32_t id, const IInputDeviceManager::IInputDevice &dev) {
            isJoystick = dev.IsJoystick();
        });
    EXPECT_TRUE(isJoystick);
}

/**
 * @tc.name: ForDevice_001
 * @tc.desc: Test the function InputDeviceManager::ForDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, ForDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    int32_t deviceId { 888 };
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
    };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    bool isJoystick { false };
    INPUT_DEV_MGR->ForDevice(deviceId,
        [&isJoystick](const IInputDeviceManager::IInputDevice &dev) {
            isJoystick = dev.IsJoystick();
        });
    EXPECT_TRUE(isJoystick);
}

/**
 * @tc.name: ForOneDevice_001
 * @tc.desc: Test the function InputDeviceManager::ForOneDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, ForOneDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    int32_t deviceId { 888 };
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
    };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    bool isJoystick { false };
    INPUT_DEV_MGR->ForOneDevice(
        [deviceId](int32_t id, const IInputDeviceManager::IInputDevice &dev) {
            return (deviceId == id);
        },
        [&isJoystick](int32_t id, const IInputDeviceManager::IInputDevice &dev) {
            isJoystick = dev.IsJoystick();
        });
    EXPECT_TRUE(isJoystick);
}

/**
 * @tc.name: Attach_001
 * @tc.desc: Test the function InputDeviceManager::Attach
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, Attach_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Attach(observer));
    EXPECT_TRUE(std::any_of(INPUT_DEV_MGR->observers_.cbegin(), INPUT_DEV_MGR->observers_.cend(),
        [observer](const auto &item) {
            return (observer == item);
        }));
}

/**
 * @tc.name: Detach_001
 * @tc.desc: Test the function InputDeviceManager::Detach
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, Detach_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    INPUT_DEV_MGR->Attach(observer);
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Detach(observer));
    EXPECT_TRUE(std::none_of(INPUT_DEV_MGR->observers_.cbegin(), INPUT_DEV_MGR->observers_.cend(),
        [observer](const auto &item) {
            return (observer == item);
        }));
}

/**
 * @tc.name: NotifyDeviceAdded_001
 * @tc.desc: Test the function InputDeviceManager::NotifyDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, NotifyDeviceAdded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    EXPECT_CALL(*observer, OnDeviceAdded).Times(testing::Exactly(1));
    INPUT_DEV_MGR->Attach(observer);
    int32_t deviceId { 1 };
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDeviceAdded(deviceId));
}

/**
 * @tc.name: NotifyDeviceRemoved_001
 * @tc.desc: Test the function InputDeviceManager::NotifyDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, NotifyDeviceRemoved_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    EXPECT_CALL(*observer, OnDeviceRemoved).Times(testing::Exactly(1));
    INPUT_DEV_MGR->Attach(observer);
    int32_t deviceId { 1 };
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDeviceRemoved(deviceId));
}
} // namespace MMI
} // namespace OHOS
