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
#include <linux/input.h>

#include "input_device_manager.h"
#include "key_auto_repeat.h"
#include "key_map_manager.h"
#include "libinput_mock.h"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

namespace {
char g_sysname[] { "event0" };
char g_sysname1[] { "event999" };
} // namespace

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
    INPUT_DEV_MGR->Detach(observer);
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
    INPUT_DEV_MGR->Detach(observer);
}

/**
 * @tc.name: PhysicalInputDevice_AddInputDevice_001
 * @tc.desc: Test PhysicalInputDevice::AddInputDevice with normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_AddInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 61 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);
    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    EXPECT_NO_FATAL_FAILURE(physicalDevice.AddInputDevice(deviceId));
    EXPECT_EQ(physicalDevice.GetInputDeviceCount(), 1u);
}

/**
 * @tc.name: PhysicalInputDevice_RemoveInputDevice_001
 * @tc.desc: Test PhysicalInputDevice::RemoveInputDevice with existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_RemoveInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 71 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    physicalDevice.AddInputDevice(deviceId);
    EXPECT_EQ(physicalDevice.GetInputDeviceCount(), 1u);

    EXPECT_NO_FATAL_FAILURE(physicalDevice.RemoveInputDevice(deviceId));
    EXPECT_EQ(physicalDevice.GetInputDeviceCount(), 0u);
}

/**
 * @tc.name: PhysicalInputDevice_RemoveInputDevice_002
 * @tc.desc: Test PhysicalInputDevice::RemoveInputDevice with non-existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_RemoveInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId1 { 71 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId1, devInfo);

    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    physicalDevice.AddInputDevice(deviceId1);
    int32_t deviceId2 { 72 };
    EXPECT_NO_FATAL_FAILURE(physicalDevice.RemoveInputDevice(deviceId2));
    EXPECT_EQ(physicalDevice.GetInputDeviceCount(), 1u);
}

/**
 * @tc.name: PhysicalInputDevice_IsEmpty_001
 * @tc.desc: Test PhysicalInputDevice::IsEmpty returns true when empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_IsEmpty_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::PhysicalInputDevice physicalDevice;
    EXPECT_TRUE(physicalDevice.IsEmpty());
}

/**
 * @tc.name: PhysicalInputDevice_IsEmpty_002
 * @tc.desc: Test PhysicalInputDevice::IsEmpty returns false when not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_IsEmpty_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 81 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    physicalDevice.AddInputDevice(deviceId);
    EXPECT_FALSE(physicalDevice.IsEmpty());
}

/**
 * @tc.name: PhysicalInputDevice_GetTags_001
 * @tc.desc: Test PhysicalInputDevice::GetTags returns default tags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetTags_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::PhysicalInputDevice physicalDevice;
    EXPECT_EQ(physicalDevice.GetTags(), 0u);
}

/**
 * @tc.name: PhysicalInputDevice_ForeachInputDevice_001
 * @tc.desc: Test PhysicalInputDevice::ForeachInputDevice callback mechanism
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_ForeachInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId1 { 101 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId1, devInfo);
    int32_t deviceId2 { 102 };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId2, devInfo);
    int32_t deviceId3 { 103 };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId3, devInfo);

    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    physicalDevice.AddInputDevice(deviceId1);
    physicalDevice.AddInputDevice(deviceId2);
    physicalDevice.AddInputDevice(deviceId3);

    int32_t sum = 0;
    physicalDevice.ForeachInputDevice([&sum](int32_t deviceId) {
        sum += deviceId;
    });
    constexpr int32_t total { 306 };
    EXPECT_EQ(sum, total);
}

/**
 * @tc.name: PhysicalInputDevice_ForeachInputDevice_002
 * @tc.desc: Test PhysicalInputDevice::ForeachInputDevice with empty device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_ForeachInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::PhysicalInputDevice physicalDevice;

    int32_t count = 0;
    physicalDevice.ForeachInputDevice([&count](int32_t deviceId) {
        count++;
    });

    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: PhysicalInputDevice_MoveConstructor_001
 * @tc.desc: Test PhysicalInputDevice move constructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_MoveConstructor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId1 { 201 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId1, devInfo);
    int32_t deviceId2 { 202 };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId2, devInfo);

    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    physicalDevice.AddInputDevice(deviceId1);
    physicalDevice.AddInputDevice(deviceId2);

    InputDeviceManager::PhysicalInputDevice movedDevice = std::move(physicalDevice);

    EXPECT_EQ(movedDevice.GetInputDeviceCount(), 2u);
    EXPECT_TRUE(physicalDevice.IsEmpty());
}

/**
 * @tc.name: PhysicalInputDevice_MoveAssignment_001
 * @tc.desc: Test PhysicalInputDevice move assignment operator
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_MoveAssignment_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId1 { 201 };
    InputDeviceManager::InputDeviceInfo devInfo {};
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId1, devInfo);

    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    physicalDevice.AddInputDevice(deviceId1);

    InputDeviceManager::PhysicalInputDevice movedDevice;
    movedDevice = std::move(physicalDevice);

    EXPECT_EQ(movedDevice.GetInputDeviceCount(), 1u);
}

/**
 * @tc.name: PhysicalInputDevice_IsPointerDevice_001
 * @tc.desc: Test PhysicalInputDevice::IsPointerDevice returns true for pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_IsPointerDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    struct libinput_device rawDev {};
    rawDev.udevDev.tags = EVDEV_UDEV_TAG_POINTINGSTICK;

    int32_t deviceId { 201 };
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
    };
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    InputDeviceManager::PhysicalInputDevice physicalDevice {};
    physicalDevice.AddInputDevice(deviceId);

    EXPECT_TRUE(physicalDevice.IsPointerDevice());
}

/**
 * @tc.name: PhysicalInputDevice_IsPointerDevice_002
 * @tc.desc: Test PhysicalInputDevice::IsPointerDevice returns false for non-pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_IsPointerDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability)
        .WillRepeatedly(Return(true));

    struct libinput_device rawDev {};
    rawDev.udevDev.tags = EVDEV_UDEV_TAG_INPUT;

    InputDeviceManager::PhysicalInputDevice physicalDevice;
    physicalDevice.AddInputDevice(100);

    EXPECT_FALSE(physicalDevice.IsPointerDevice());
}

/**
 * @tc.name: UpdateInputDeviceCaps_001
 * @tc.desc: Test InputDeviceManager::UpdateInputDeviceCaps with normal device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, UpdateInputDeviceCaps_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability)
        .WillRepeatedly(Return(true));

    int32_t deviceId = 100;
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
        .physicalId = "test_physical_001",
    };

    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->UpdateInputDeviceCaps(deviceId));
}

/**
 * @tc.name: UpdateInputDeviceCaps_002
 * @tc.desc: Test InputDeviceManager::UpdateInputDeviceCaps with non-existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, UpdateInputDeviceCaps_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 999;
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->UpdateInputDeviceCaps(deviceId));
}

/**
 * @tc.name: AddPhysicalInputDeviceInner_001
 * @tc.desc: Test AddPhysicalInputDeviceInner calls UpdateInputDeviceCapabilities
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, AddPhysicalInputDeviceInner_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    int32_t deviceId { 101 };
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
        .physicalId = "test_physical_002",
    };

    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    auto device = INPUT_DEV_MGR->GetInputDevice(deviceId, false);
    EXPECT_NE(device, nullptr);
    const auto &physicalInputDevices = INPUT_DEV_MGR->physicalInputDevices_;
    auto physIter = physicalInputDevices.find(devInfo.physicalId);
    EXPECT_TRUE(physIter != physicalInputDevices.cend());
    if (physIter != physicalInputDevices.cend()) {
        const auto &deviceIds = physIter->second.inputDeviceIds_;
        EXPECT_TRUE(deviceIds.find(deviceId) != deviceIds.cend());
    }
}

/**
 * @tc.name: AddPhysicalInputDeviceInner_002
 * @tc.desc: Test AddPhysicalInputDeviceInner with multiple devices in same physical group
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, AddPhysicalInputDeviceInner_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability)
        .WillRepeatedly(Return(true));

    std::string physicalId { "test_physical_003" };
    int32_t deviceId1 { 651 };
    int32_t deviceId2 { 652 };
    struct libinput_device rawDev1 {};
    struct libinput_device rawDev2 {};

    InputDeviceManager::InputDeviceInfo devInfo1 {
        .inputDeviceOrigin = &rawDev1,
        .physicalId = physicalId,
    };

    InputDeviceManager::InputDeviceInfo devInfo2 {
        .inputDeviceOrigin = &rawDev2,
        .physicalId = physicalId,
    };

    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId1, devInfo1);
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId2, devInfo2);

    auto device1 = INPUT_DEV_MGR->GetInputDevice(deviceId1, false);
    auto device2 = INPUT_DEV_MGR->GetInputDevice(deviceId2, false);
    EXPECT_NE(device1, nullptr);
    EXPECT_NE(device2, nullptr);
}

/**
 * @tc.name: CheckInputDeviceCaps_001
 * @tc.desc: Test InputDeviceManager::CheckInputDeviceCaps with keyboard device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, CheckInputDeviceCaps_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability)
        .WillRepeatedly([](struct libinput_device*, enum libinput_device_capability cap) {
            return cap == LIBINPUT_DEVICE_CAP_KEYBOARD;
        });

    int32_t deviceId { 103 };
    struct libinput_device rawDev {};
    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
        .physicalId = "test_physical_004",
    };

    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->CheckInputDeviceCaps(deviceId));
}

/**
 * @tc.name: RemoveInputDeviceFromPhysicalDevice_001
 * @tc.desc: Test RemoveInputDeviceFromPhysicalDevice with valid physicalId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, RemoveInputDeviceFromPhysicalDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    std::string physicalId { "test_physical_005" };
    int32_t deviceId { 104 };
    struct libinput_device rawDev {};

    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
        .physicalId = physicalId,
    };

    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    const auto &physicalInputDevices = INPUT_DEV_MGR->physicalInputDevices_;
    auto physIter = physicalInputDevices.find(devInfo.physicalId);
    EXPECT_TRUE(physIter != physicalInputDevices.cend());
    if (physIter != physicalInputDevices.cend()) {
        const auto &deviceIds = physIter->second.inputDeviceIds_;
        EXPECT_TRUE(deviceIds.find(deviceId) != deviceIds.cend());
    }

    INPUT_DEV_MGR->RemoveInputDeviceFromPhysicalDevice(deviceId, physicalId);
    EXPECT_TRUE(physicalInputDevices.find(devInfo.physicalId) == physicalInputDevices.cend());
}

/**
 * @tc.name: GetPhysicalInputDevice_001
 * @tc.desc: Test GetPhysicalInputDevice returns existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, GetPhysicalInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    std::string physicalId { "test_physical_006" };
    int32_t deviceId { 105 };
    struct libinput_device rawDev {};

    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
        .physicalId = physicalId,
    };

    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(deviceId, devInfo);

    auto* physicalDevice = INPUT_DEV_MGR->GetPhysicalInputDevice(physicalId);
    EXPECT_NE(physicalDevice, nullptr);
    EXPECT_EQ(physicalDevice->GetInputDeviceCount(), 1u);
}

/**
 * @tc.name: GetPhysicalInputDevice_002
 * @tc.desc: Test GetPhysicalInputDevice returns nullptr for non-existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, GetPhysicalInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto* physicalDevice = INPUT_DEV_MGR->GetPhysicalInputDevice("non_existing_physical_id");
    EXPECT_EQ(physicalDevice, nullptr);
}

/**
 * @tc.name: UpdatePhysicalInputDevice_001
 * @tc.desc: Test UpdatePhysicalInputDevice with new device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, UpdatePhysicalInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceHasCapability).WillRepeatedly(Return(true));

    std::string physicalId { "test_physical_007" };
    int32_t deviceId { 106 };
    struct libinput_device rawDev {};

    InputDeviceManager::InputDeviceInfo devInfo {
        .inputDeviceOrigin = &rawDev,
        .physicalId = physicalId,
    };

    INPUT_DEV_MGR->UpdatePhysicalInputDevice(deviceId, devInfo);

    auto* physicalDevice = INPUT_DEV_MGR->GetPhysicalInputDevice(physicalId);
    EXPECT_NE(physicalDevice, nullptr);
}

/**
 * @tc.name: PhysicalInputDevice_GetId_001
 * @tc.desc: Test PhysicalInputDevice::GetId with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(InputDeviceManager::PhysicalInputDevice::GetId(nullptr).empty());
}

/**
 * @tc.name: PhysicalInputDevice_GetId_002
 * @tc.desc: Test PhysicalInputDevice::GetId with vendor and product both 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device device {};
    device.vendor = 0;
    device.product = 0;
    EXPECT_TRUE(InputDeviceManager::PhysicalInputDevice::GetId(&device).empty());
}

/**
 * @tc.name: PhysicalInputDevice_GetId_003
 * @tc.desc: Test PhysicalInputDevice::GetId with vendor and product both non-0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetId_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetSysname).WillOnce(Return(g_sysname1));

    struct libinput_device device {
        .busType = BUS_USB,
        .vendor = 1,
        .product = 1,
    };
    auto physicalId = InputDeviceManager::PhysicalInputDevice::GetId(&device);
    EXPECT_TRUE(physicalId.empty());
}

/**
 * @tc.name: PhysicalInputDevice_GetId_004
 * @tc.desc: Test PhysicalInputDevice::GetId with vendor and product both non-0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetId_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetSysname).WillOnce(Return(g_sysname));

    struct libinput_device device {
        .busType = BUS_USB,
        .vendor = 1,
        .product = 1,
    };
    auto physicalId = InputDeviceManager::PhysicalInputDevice::GetId(&device);
    EXPECT_FALSE(physicalId.empty());
}

/**
 * @tc.name: PhysicalInputDevice_GetSyspath_001
 * @tc.desc: Test PhysicalInputDevice::GetSyspath with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetSyspath_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(InputDeviceManager::PhysicalInputDevice::GetSyspath(nullptr).empty());
}

/**
 * @tc.name: PhysicalInputDevice_GetSyspath_002
 * @tc.desc: Test PhysicalInputDevice::GetSyspath with null sysname
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetSyspath_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetSysname).WillOnce(Return(nullptr));

    struct libinput_device device {};
    EXPECT_TRUE(InputDeviceManager::PhysicalInputDevice::GetSyspath(&device).empty());
}

/**
 * @tc.name: PhysicalInputDevice_GetSyspath_003
 * @tc.desc: Test PhysicalInputDevice::GetSyspath with valid sysname
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, PhysicalInputDevice_GetSyspath_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetSysname).WillOnce(Return(g_sysname));

    struct libinput_device device {};
    auto syspath = InputDeviceManager::PhysicalInputDevice::GetSyspath(&device);
    EXPECT_FALSE(syspath.empty());
}
} // namespace MMI
} // namespace OHOS
