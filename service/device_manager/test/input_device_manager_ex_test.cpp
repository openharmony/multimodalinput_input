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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fstream>

#include "input_device_manager.h"
#include "libinput_mock.h"
#include "pointer_device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class InputDeviceManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MockIDeviceObserver : public IDeviceObserver {
public:
    MOCK_METHOD1(OnDeviceAdded, void(int32_t deviceId));
    MOCK_METHOD1(OnDeviceRemoved, void(int32_t deviceId));
    MOCK_METHOD3(UpdatePointerDevice, void(bool, bool, bool));
};

/**
 * @tc.name: NotifyDevCallback_Test_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyDevCallback_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo inDevice;
    inDevice.inputDeviceOrigin = nullptr;
    inDevice.isTouchableDevice = true;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevCallback(deviceId, inDevice));
}

/**
 * @tc.name: NotifyDevCallback_Test_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyDevCallback_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo inDevice;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    inDevice.inputDeviceOrigin = &libDev;
    inDevice.isTouchableDevice = true;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(const_cast<char*>("test")));
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevCallback(deviceId, inDevice));
}

/**
 * @tc.name: NotifyDevRemoveCallback_Test_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyDevRemoveCallback_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    using InputDeviceCallback = std::function<void(int, std::string, std::string, std::string)>;
    InputDeviceCallback callback =
        [] (int status, std::string nodeName, const std::string& deviceName, const std::string& deviceId) {};
    INPUT_DEV_MGR->SetInputStatusChangeCallback(callback);

    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo inDevice;
    inDevice.inputDeviceOrigin = nullptr;
    inDevice.sysUid = "test";
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevRemoveCallback(deviceId, inDevice));
}

/**
 * @tc.name: NotifyDevRemoveCallback_Test_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyDevRemoveCallback_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    using InputDeviceCallback = std::function<void(int, std::string, std::string, std::string)>;
    InputDeviceCallback callback =
        [] (int status, std::string nodeName, const std::string& deviceName, const std::string& deviceId) {};
    INPUT_DEV_MGR->SetInputStatusChangeCallback(callback);

    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo inDevice;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    inDevice.inputDeviceOrigin = &libDev;
    inDevice.sysUid = "test";
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(const_cast<char*>("test")));
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevRemoveCallback(deviceId, inDevice));
}

/**
 * @tc.name: IsPointerDevice_Test_001
 * @tc.desc: Test the function IsPointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, IsPointerDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device *device = nullptr;
    bool ret = INPUT_DEV_MGR->IsPointerDevice(device);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: InputDeviceManagerTest_OnInputDeviceRemoved_Test_001
 * @tc.desc: Test the function OnInputDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnInputDeviceRemoved_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    POINTER_DEV_MGR.isInit = false;
    NiceMock<LibinputInterfaceMock> libinputMock;

    int32_t deviceId1 = 1;
    int32_t deviceId2 = 2;
    int32_t deviceId3 = 3;
    InputDeviceManager::InputDeviceInfo info1;
    InputDeviceManager::InputDeviceInfo info2;
    InputDeviceManager::InputDeviceInfo info3;
    struct libinput_device libDev1 {
        .udevDev { 4 },
        .name = "test1",
    };
    struct libinput_device libDev2 {
        .udevDev { 4 },
        .name = "test2",
    };
    struct libinput_device libDev3 {
        .udevDev { 4 },
        .name = "test3",
    };
    EXPECT_CALL(libinputMock, DeviceGetUdevDevice)
        .WillOnce(Return(&libDev1.udevDev))
        .WillOnce(Return(&libDev2.udevDev))
        .WillOnce(Return(&libDev3.udevDev));
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(const_cast<char*>("test")));
    info1.inputDeviceOrigin = &libDev1;
    info1.isDeviceReportEvent = true;
    info2.inputDeviceOrigin = &libDev2;
    info2.isDeviceReportEvent = false;
    info3.inputDeviceOrigin = &libDev3;
    info3.isDeviceReportEvent = true;
    info3.isRemote = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId1, info1));
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId2, info2));
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId3, info3));
    INPUT_DEV_MGR->OnInputDeviceRemoved(&libDev1);
    ASSERT_EQ(INPUT_DEV_MGR->inputDevice_.count(deviceId1), 0);
    INPUT_DEV_MGR->OnInputDeviceRemoved(&libDev2);
    ASSERT_EQ(INPUT_DEV_MGR->inputDevice_.count(deviceId2), 0);
    INPUT_DEV_MGR->OnInputDeviceRemoved(&libDev3);
    ASSERT_EQ(INPUT_DEV_MGR->inputDevice_.count(deviceId3), 0);
}

/**
 * @tc.name: InputDeviceManagerTest_SetIsDeviceReportEvent_001
 * @tc.desc: Test the function SetIsDeviceReportEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetIsDeviceReportEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager inputDeviceManager;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo info;
    inputDeviceManager.inputDevice_.insert(std::make_pair(deviceId, info));
    int32_t virtualDeviceId = 2;
    auto virtualDevice = std::make_shared<InputDevice>();
    virtualDevice->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    inputDeviceManager.virtualInputDevices_[virtualDeviceId] = virtualDevice;
    inputDeviceManager.SetIsDeviceReportEvent(deviceId, true);
    EXPECT_EQ(inputDeviceManager.inputDevice_[deviceId].isDeviceReportEvent, true);
}

/**
 * @tc.name: NotifyDeviceAdded_Test_001
 * @tc.desc: Test the function NotifyDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyDeviceAdded_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<MockIDeviceObserver>();
    INPUT_DEV_MGR->Attach(observer);
    std::shared_ptr<IDeviceObserver> observerNull = nullptr;
    INPUT_DEV_MGR->Attach(observerNull);

    int32_t deviceId = 600;
    EXPECT_CALL(*observer, OnDeviceAdded(_)).Times(1);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDeviceAdded(deviceId));

    EXPECT_CALL(*observer, OnDeviceRemoved(_)).Times(1);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDeviceRemoved(deviceId));
}

/**
 * @tc.name: InputDeviceManagerTest_SetSpecialVirtualDevice_001
 * @tc.desc: Test SetSpecialVirtualDevice with nullptr input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetSpecialVirtualDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager inputDeviceManager;
    std::shared_ptr<InputDevice> device = nullptr;
    ASSERT_NO_FATAL_FAILURE(inputDeviceManager.SetSpecialVirtualDevice(device));
}
 
/**
 * @tc.name: InputDeviceManagerTest_SetSpecialVirtualDevice_002
 * @tc.desc: Test SetSpecialVirtualDevice with VirtualKeyboard on fold PC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetSpecialVirtualDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager inputDeviceManager;
    auto device = std::make_shared<InputDevice>();
    device->SetName("VirtualKeyboard");
    inputDeviceManager.SetSpecialVirtualDevice(device);
    EXPECT_EQ(device->IsVirtual(), true);
}
 
/**
 * @tc.name: InputDeviceManagerTest_SetSpecialVirtualDevice_003
 * @tc.desc: Test SetSpecialVirtualDevice with VirtualTrackpad on fold PC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetSpecialVirtualDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager inputDeviceManager;
    auto device = std::make_shared<InputDevice>();
    device->SetName("VirtualTrackpad");
    inputDeviceManager.SetSpecialVirtualDevice(device);
    EXPECT_EQ(device->IsVirtual(), true);
}
 
/**
 * @tc.name: InputDeviceManagerTest_SetSpecialVirtualDevice_004
 * @tc.desc: Test SetSpecialVirtualDevice with other virtual device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetSpecialVirtualDevice_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager inputDeviceManager;
    auto device = std::make_shared<InputDevice>();
    device->SetName("OtherDevice");
    inputDeviceManager.SetSpecialVirtualDevice(device);
    EXPECT_EQ(device->IsVirtual(), true);
}
} // namespace MMI
} // namespace OHOS