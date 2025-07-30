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
#include "libinput.h"
 
struct udev_device {
    uint32_t tags;
};
 
struct libinput_device {
    struct udev_device udevDev;
    unsigned int busType;
    unsigned int version;
    unsigned int product;
    unsigned int vendor;
    char name[9];
};
 
extern "C" {
const char *libinput_device_get_name(struct libinput_device *device)
{
    const char* pName = device->name;
    return pName;
}
}
 
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo inDevice;
    inDevice.inputDeviceOrigin = nullptr;
    inDevice.isTouchableDevice = true;
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevCallback(deviceId, inDevice));
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
    InputDeviceManager inputDevice;
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
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevCallback(deviceId, inDevice));
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
    InputDeviceManager inputDevice;
    using InputDeviceCallback = std::function<void(int, std::string, std::string, std::string)>;
    InputDeviceCallback callback =
        [] (int status, std::string nodeName, const std::string& deviceName, const std::string& deviceId) {};
    inputDevice.SetInputStatusChangeCallback(callback);
 
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo inDevice;
    inDevice.inputDeviceOrigin = nullptr;
    inDevice.sysUid = "test";
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevRemoveCallback(deviceId, inDevice));
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
    InputDeviceManager inputDevice;
    using InputDeviceCallback = std::function<void(int, std::string, std::string, std::string)>;
    InputDeviceCallback callback =
        [] (int status, std::string nodeName, const std::string& deviceName, const std::string& deviceId) {};
    inputDevice.SetInputStatusChangeCallback(callback);
 
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
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevRemoveCallback(deviceId, inDevice));
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
    InputDeviceManager inputDevice;
    auto observer = std::make_shared<MockIDeviceObserver>();
    inputDevice.Attach(observer);
    std::shared_ptr<IDeviceObserver> observerNull = nullptr;
    inputDevice.Attach(observerNull);

    int32_t deviceId = 600;
    EXPECT_CALL(*observer, OnDeviceAdded(_)).Times(1);
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDeviceAdded(deviceId));

    EXPECT_CALL(*observer, OnDeviceRemoved(_)).Times(1);
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDeviceRemoved(deviceId));
}
} // namespace MMI
} // namespace OHOS