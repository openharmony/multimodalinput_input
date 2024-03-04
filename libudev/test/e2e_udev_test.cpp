/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <atomic>
#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "input_manager.h"
#include "test_device.h"

using namespace std::chrono_literals;
using ::testing::ext::TestSize;
namespace {
constexpr auto DEVICE_MAX_DELAY = 100ms;
constexpr auto DEVICE_DELAY_STEP = 10ms;
} // namespace

class TestDeviceListener : public OHOS::MMI::IInputDeviceListener {
public:
    ~TestDeviceListener() override = default;
    void OnDeviceAdded(int32_t deviceId, const std::string& type)
    {
        added_ = true;
        deviceId_ = deviceId;
    }
    void OnDeviceRemoved(int32_t deviceId, const std::string& type)
    {
        removed_ = true;
        deviceId_ = deviceId;
    }

    void Clear()
    {
        added_ = false;
        removed_ = false;
        deviceId_ = -1;
    }

    std::atomic<bool> added_ = false;
    std::atomic<bool> removed_ = false;
    std::atomic<int32_t> deviceId_ = -1;
};

class E2eUdevTest : public ::testing::Test {
public:
    static void SetUpTestSuite()
    {
        inputManager_->RegisterDevListener("change", listener_);
    }

    static void TearDownTestSuite()
    {
        inputManager_->UnregisterDevListener("change", listener_);
    }

    bool WaitAdded()
    {
        auto till = std::chrono::steady_clock::now() + DEVICE_MAX_DELAY;
        while (!listener_->added_ && std::chrono::steady_clock::now() < till) {
            std::this_thread::sleep_for(DEVICE_DELAY_STEP);
        }
        return listener_->added_;
    }

    void SetUp() override
    {
        listener_->Clear();
    }

    void TearDown() override
    {
        if (!listener_->added_) {
            return;
        }
        testDevice_.Destroy();
        auto till = std::chrono::steady_clock::now() + DEVICE_MAX_DELAY;
        while (!listener_->removed_ && std::chrono::steady_clock::now() < till) {
            std::this_thread::sleep_for(DEVICE_DELAY_STEP);
        }
    }

    inline static OHOS::MMI::InputManager* inputManager_ = OHOS::MMI::InputManager::GetInstance();
    inline static std::shared_ptr<TestDeviceListener> listener_ = std::make_shared<TestDeviceListener>();
    TestDevice testDevice_;
};

HWTEST_F(E2eUdevTest, TestUdevPropsDefault, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init());
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetName(), TestDevice::TEST_NAME);
        EXPECT_EQ(dev->GetBus(), TestDevice::TEST_BUS);
        EXPECT_EQ(dev->GetVendor(), TestDevice::TEST_VENDOR);
        EXPECT_EQ(dev->GetProduct(), TestDevice::TEST_PRODUCT);
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_POINTER);
    });
    EXPECT_EQ(res, 0);
}

HWTEST_F(E2eUdevTest, TestUdevPropsKey, TestSize.Level1)
{
    testDevice_.KeyboardSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_KEYBOARD);
    });
    EXPECT_EQ(res, 0);
}

HWTEST_F(E2eUdevTest, TestUdevPropsSwitch, TestSize.Level1)
{
    testDevice_.SwitchSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_SWITCH);
    });
    EXPECT_EQ(res, 0);
}

HWTEST_F(E2eUdevTest, TestUdevPropsAccel, TestSize.Level1)
{
    testDevice_.AccelerometerSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_FALSE(WaitAdded());
}

HWTEST_F(E2eUdevTest, TestUdevPropsStick, TestSize.Level1)
{
    testDevice_.StickSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_POINTER);
    });
    EXPECT_EQ(res, 0);
}

HWTEST_F(E2eUdevTest, TestUdevPropsTouchpad, TestSize.Level1)
{
    testDevice_.TouchpadSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_POINTER);
    });
    EXPECT_EQ(res, 0);
}

HWTEST_F(E2eUdevTest, TestUdevPropsTouchscreen, TestSize.Level1)
{
    testDevice_.TouchscreenSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_TOUCH);
    });
    EXPECT_EQ(res, 0);
}

HWTEST_F(E2eUdevTest, TestUdevPropsJoystick, TestSize.Level1)
{
    testDevice_.JoystickSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_JOYSTICK);
    });
    EXPECT_EQ(res, 0);
}

HWTEST_F(E2eUdevTest, TestUdevPropsTablet, TestSize.Level1)
{
    testDevice_.TabletSetup();
    ASSERT_NO_FATAL_FAILURE(testDevice_.Init(false));
    ASSERT_TRUE(WaitAdded());
    EXPECT_GE(listener_->deviceId_, 0);

    auto res = inputManager_->GetDevice(listener_->deviceId_, [](std::shared_ptr<OHOS::MMI::InputDevice> dev) {
        EXPECT_EQ(dev->GetCapabilities(), 1ULL << OHOS::MMI::INPUT_DEV_CAP_TABLET_TOOL);
    });
    EXPECT_EQ(res, 0);
}
