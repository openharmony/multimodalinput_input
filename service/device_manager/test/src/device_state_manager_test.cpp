/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <linux/input.h>
#include "gtest/gtest.h"

#include "define_multimodal.h"
#include "device_state_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DeviceStateManagerTest"

namespace OHOS {
namespace MMI {
using namespace testing::ext;

class DeviceStateManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void DeviceStateManagerTest::SetUpTestCase()
{}

void DeviceStateManagerTest::TearDownTestCase()
{}

/**
 * @tc.name: DeviceStateManagerTest_GetInstance_001
 * @tc.desc: Test the function GetInstance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_GetInstance_001, TestSize.Level1)
{
    auto instance1 = DeviceStateManager::GetInstance();
    ASSERT_NE(instance1, nullptr);

    auto instance2 = DeviceStateManager::GetInstance();
    EXPECT_EQ(instance1, instance2);
}

/**
 * @tc.name: DeviceStateManagerTest_AddTouches_001
 * @tc.desc: Test the function AddTouches when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddTouches_001, TestSize.Level1)
{
    const int32_t deviceId { 1 };
    std::set<int32_t> touches { 1, 2, 3 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.touches_.size(), touches.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AddTouches_002
 * @tc.desc: Test the function AddTouches when device exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddTouches_002, TestSize.Level1)
{
    const int32_t deviceId { 2 };
    std::set<int32_t> touches1 { 1, 2 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches1);

    std::set<int32_t> touches2 { 3, 4 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches2);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        const size_t nTouches { 4 };
        EXPECT_EQ(iter->second.touches_.size(), nTouches);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AddPressedButtons_001
 * @tc.desc: Test the function AddPressedButtons when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddPressedButtons_001, TestSize.Level1)
{
    const int32_t deviceId { 3 };
    std::set<int32_t> buttons { BTN_LEFT, BTN_RIGHT };
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedButtons_.size(), buttons.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AddPressedButtons_002
 * @tc.desc: Test the function AddPressedButtons when device exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddPressedButtons_002, TestSize.Level1)
{
    const int32_t deviceId { 4 };
    std::set<int32_t> buttons1 { BTN_LEFT };
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons1);

    std::set<int32_t> buttons2 { BTN_RIGHT };
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons2);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        const size_t nPressedButtons { 2 };
        EXPECT_EQ(iter->second.pressedButtons_.size(), nPressedButtons);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AddPressedKeys_001
 * @tc.desc: Test the function AddPressedKeys when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddPressedKeys_001, TestSize.Level1)
{
    const int32_t deviceId { 5 };
    std::set<int32_t> keys { KEY_A, KEY_B };
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedKeys_.size(), keys.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AddPressedKeys_002
 * @tc.desc: Test the function AddPressedKeys when device exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddPressedKeys_002, TestSize.Level1)
{
    const int32_t deviceId { 6 };
    std::set<int32_t> keys1 { KEY_A };
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys1);

    std::set<int32_t> keys2 { KEY_B };
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys2);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        const size_t nPressedKeys { 2 };
        EXPECT_EQ(iter->second.pressedKeys_.size(), nPressedKeys);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_SetProximity_001
 * @tc.desc: Test the function SetProximity when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SetProximity_001, TestSize.Level1)
{
    const int32_t deviceId { 7 };
    DeviceStateManager::GetInstance()->SetProximity(deviceId, true);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.isProximity_);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_SetProximity_002
 * @tc.desc: Test the function SetProximity when device exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SetProximity_002, TestSize.Level1)
{
    const int32_t deviceId { 8 };
    DeviceStateManager::GetInstance()->SetProximity(deviceId, true);
    DeviceStateManager::GetInstance()->SetProximity(deviceId, false);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_FALSE(iter->second.isProximity_);
        EXPECT_FALSE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_SetAxisBegin_001
 * @tc.desc: Test the function SetAxisBegin when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SetAxisBegin_001, TestSize.Level1)
{
    const int32_t deviceId { 9 };
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, true);
    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.isAxisBegin_);
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_SetAxisBegin_002
 * @tc.desc: Test the function SetAxisBegin when device exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SetAxisBegin_002, TestSize.Level1)
{
    const int32_t deviceId { 10 };
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, true);
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, false);
    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_FALSE(iter->second.isAxisBegin_);
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_EnableDevice_001
 * @tc.desc: Test the function EnableDevice when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableDevice_001, TestSize.Level1)
{
    const int32_t deviceId { 11 };
    bool callbackCalled { false };
    int32_t callbackDeviceId { -1 };
    auto callback = [&callbackCalled, &callbackDeviceId](int32_t id) -> int32_t {
        callbackCalled = true;
        callbackDeviceId = id;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackDeviceId, deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_EnableDevice_002
 * @tc.desc: Test the function EnableDevice when device exists and has no active operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableDevice_002, TestSize.Level1)
{
    const int32_t deviceId { 12 };
    DeviceStateManager::GetInstance()->SetProximity(deviceId, false);

    bool callbackCalled { false };
    int32_t callbackDeviceId { -1 };
    auto callback = [&callbackCalled, &callbackDeviceId](int32_t id) -> int32_t {
        callbackCalled = true;
        callbackDeviceId = id;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackDeviceId, deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_EnableDevice_003
 * @tc.desc: Test the function EnableDevice when device exists and has active operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableDevice_003, TestSize.Level1)
{
    const int32_t deviceId { 13 };
    std::set<int32_t> touches { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    bool callbackCalled { false };
    auto callback = [&callbackCalled](int32_t id) -> int32_t {
        callbackCalled = true;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);
    EXPECT_FALSE(callbackCalled);
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_EnableDevice_004
 * @tc.desc: Test the function EnableDevice with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableDevice_004, TestSize.Level1)
{
    const int32_t deviceId { 14 };
    DeviceStateManager::GetInstance()->EnableDevice(deviceId, nullptr);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_FALSE(iter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_DisableDevice_001
 * @tc.desc: Test the function DisableDevice when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_DisableDevice_001, TestSize.Level1)
{
    const int32_t deviceId { 15 };
    DeviceStateManager::GetInstance()->DisableDevice(deviceId);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_FALSE(iter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_DisableDevice_002
 * @tc.desc: Test the function DisableDevice when device exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_DisableDevice_002, TestSize.Level1)
{
    const int32_t deviceId { 16 };
    std::set<int32_t> touches { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);
    DeviceStateManager::GetInstance()->DisableDevice(deviceId);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    if (iter != deviceStates.cend()) {
        EXPECT_FALSE(iter->second.IsEnabled());
    }
    EXPECT_TRUE(iter != deviceStates.cend());
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_OnDeviceRemoved_001
 * @tc.desc: Test the function OnDeviceRemoved when device exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_OnDeviceRemoved_001, TestSize.Level1)
{
    const int32_t deviceId { 17 };
    std::set<int32_t> touches { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iterBefore = deviceStates.find(deviceId);
    EXPECT_TRUE(iterBefore != deviceStates.cend());

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_OnDeviceRemoved_002
 * @tc.desc: Test the function OnDeviceRemoved when device not exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_OnDeviceRemoved_002, TestSize.Level1)
{
    const int32_t deviceId { -1 };
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_FALSE(iter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_HaveActiveOperations_001
 * @tc.desc: Test active operations when touches not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_HaveActiveOperations_001, TestSize.Level1)
{
    const int32_t deviceId { 18 };
    std::set<int32_t> touches { 1, 2, 3 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.HaveActiveOperations());
        EXPECT_EQ(iter->second.touches_.size(), touches.size());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_HaveActiveOperations_002
 * @tc.desc: Test active operations when pressed buttons not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_HaveActiveOperations_002, TestSize.Level1)
{
    const int32_t deviceId { 19 };
    std::set<int32_t> buttons { BTN_LEFT, BTN_RIGHT };
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.HaveActiveOperations());
        EXPECT_EQ(iter->second.pressedButtons_.size(), buttons.size());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_HaveActiveOperations_003
 * @tc.desc: Test active operations when pressed keys not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_HaveActiveOperations_003, TestSize.Level1)
{
    const int32_t deviceId { 20 };
    std::set<int32_t> keys { KEY_A, KEY_B };
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.HaveActiveOperations());
        EXPECT_EQ(iter->second.pressedKeys_.size(), keys.size());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_HaveActiveOperations_004
 * @tc.desc: Test active operations when proximity is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_HaveActiveOperations_004, TestSize.Level1)
{
    const int32_t deviceId { 21 };
    DeviceStateManager::GetInstance()->SetProximity(deviceId, true);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.HaveActiveOperations());
        EXPECT_TRUE(iter->second.isProximity_);
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_HaveActiveOperations_005
 * @tc.desc: Test active operations when all states are false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_HaveActiveOperations_005, TestSize.Level1)
{
    const int32_t deviceId { 22 };
    DeviceStateManager::GetInstance()->SetProximity(deviceId, false);
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, false);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_FALSE(iter->second.HaveActiveOperations());
        EXPECT_FALSE(iter->second.isProximity_);
        EXPECT_FALSE(iter->second.isAxisBegin_);
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_MultipleDevices_001
 * @tc.desc: Test operations on multiple devices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_MultipleDevices_001, TestSize.Level1)
{
    const int32_t deviceId1 { 23 };
    const int32_t deviceId2 { 24 };
    std::set<int32_t> touches1 { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId1, touches1);

    std::set<int32_t> touches2 { 2 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId2, touches2);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter1 = deviceStates.find(deviceId1);
    auto iter2 = deviceStates.find(deviceId2);
    EXPECT_TRUE(iter1 != deviceStates.cend());
    EXPECT_TRUE(iter2 != deviceStates.cend());

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId1);
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId2);

    auto iter1After = deviceStates.find(deviceId1);
    auto iter2After = deviceStates.find(deviceId2);
    EXPECT_FALSE(iter1After != deviceStates.cend());
    EXPECT_FALSE(iter2After != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_EnableDisable_001
 * @tc.desc: Test enable and disable sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableDisable_001, TestSize.Level1)
{
    const int32_t deviceId { 25 };
    std::set<int32_t> touches { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    bool callbackCalled { false };
    auto callback = [&callbackCalled](int32_t id) -> int32_t {
        callbackCalled = true;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);
    EXPECT_FALSE(callbackCalled);

    DeviceStateManager::GetInstance()->DisableDevice(deviceId);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    if (iter != deviceStates.cend()) {
        EXPECT_FALSE(iter->second.IsEnabled());
    }
    EXPECT_TRUE(iter != deviceStates.cend());
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_NotifyEnabled_001
 * @tc.desc: Test NotifyEnabled callback invoked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_NotifyEnabled_001, TestSize.Level1)
{
    const int32_t deviceId { 26 };
    std::set<int32_t> touches { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    bool callbackCalled { false };
    int32_t callbackDeviceId { -1 };
    auto callback = [&callbackCalled, &callbackDeviceId](int32_t id) -> int32_t {
        callbackCalled = true;
        callbackDeviceId = id;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_AddTouches_003
 * @tc.desc: Test the function AddTouches with empty set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddTouches_003, TestSize.Level1)
{
    const int32_t deviceId { 27 };
    std::set<int32_t> touches {};
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.touches_.size(), touches.size());
        EXPECT_FALSE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AddPressedButtons_003
 * @tc.desc: Test the function AddPressedButtons with empty set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddPressedButtons_003, TestSize.Level1)
{
    const int32_t deviceId { 28 };
    std::set<int32_t> buttons {};
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedButtons_.size(), buttons.size());
        EXPECT_FALSE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AddPressedKeys_003
 * @tc.desc: Test the function AddPressedKeys with empty set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AddPressedKeys_003, TestSize.Level1)
{
    const int32_t deviceId { 29 };
    std::set<int32_t> keys {};
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedKeys_.size(), keys.size());
        EXPECT_FALSE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_SetAxisBegin_003
 * @tc.desc: Test the function SetAxisBegin with true value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SetAxisBegin_003, TestSize.Level1)
{
    const int32_t deviceId { 30 };
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, true);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.isAxisBegin_);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_EnableDevice_005
 * @tc.desc: Test the function EnableDevice with callback return value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableDevice_005, TestSize.Level1)
{
    const int32_t deviceId { 31 };
    int32_t returnValue { -1 };
    auto callback = [&returnValue](int32_t id) -> int32_t {
        returnValue = RET_OK;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_FALSE(iter != deviceStates.cend());

    EXPECT_EQ(returnValue, RET_OK);
}

/**
 * @tc.name: DeviceStateManagerTest_MultipleOperations_001
 * @tc.desc: Test multiple operations on same device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_MultipleOperations_001, TestSize.Level1)
{
    const int32_t deviceId { 32 };
    std::set<int32_t> touches { 1, 2 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    std::set<int32_t> buttons { BTN_LEFT };
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons);

    std::set<int32_t> keys { KEY_A };
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys);

    DeviceStateManager::GetInstance()->SetProximity(deviceId, true);
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, true);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.touches_.size(), touches.size());
        EXPECT_EQ(iter->second.pressedButtons_.size(), buttons.size());
        EXPECT_EQ(iter->second.pressedKeys_.size(), keys.size());
        EXPECT_TRUE(iter->second.isProximity_);
        EXPECT_TRUE(iter->second.isAxisBegin_);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_SingleTouch_001
 * @tc.desc: Test single touch add and remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SingleTouch_001, TestSize.Level1)
{
    const int32_t deviceId { 33 };
    std::set<int32_t> touches { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.touches_.size(), touches.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_MultipleTouches_001
 * @tc.desc: Test multiple touches add and remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_MultipleTouches_001, TestSize.Level1)
{
    const int32_t deviceId { 34 };
    std::set<int32_t> touches { 1, 2, 3, 4, 5 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.touches_.size(), touches.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_SingleButton_001
 * @tc.desc: Test single button add and remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SingleButton_001, TestSize.Level1)
{
    const int32_t deviceId { 35 };
    std::set<int32_t> buttons { BTN_LEFT };
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedButtons_.size(), buttons.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_MultipleButtons_001
 * @tc.desc: Test multiple buttons add and remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_MultipleButtons_001, TestSize.Level1)
{
    const int32_t deviceId { 36 };
    std::set<int32_t> buttons { BTN_LEFT, BTN_RIGHT, BTN_MIDDLE };
    DeviceStateManager::GetInstance()->AddPressedButtons(deviceId, buttons);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedButtons_.size(), buttons.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_SingleKey_001
 * @tc.desc: Test single key add and remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_SingleKey_001, TestSize.Level1)
{
    const int32_t deviceId { 37 };
    std::set<int32_t> keys { KEY_A };
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedKeys_.size(), keys.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_MultipleKeys_001
 * @tc.desc: Test multiple keys add and remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_MultipleKeys_001, TestSize.Level1)
{
    const int32_t deviceId { 38 };
    std::set<int32_t> keys { KEY_A, KEY_B, KEY_C, KEY_D };
    DeviceStateManager::GetInstance()->AddPressedKeys(deviceId, keys);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.pressedKeys_.size(), keys.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);

    auto iterAfter = deviceStates.find(deviceId);
    EXPECT_FALSE(iterAfter != deviceStates.cend());
}

/**
 * @tc.name: DeviceStateManagerTest_Proximity_003
 * @tc.desc: Test proximity state switch multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_Proximity_003, TestSize.Level1)
{
    const int32_t deviceId { 39 };
    DeviceStateManager::GetInstance()->SetProximity(deviceId, true);
    DeviceStateManager::GetInstance()->SetProximity(deviceId, false);
    DeviceStateManager::GetInstance()->SetProximity(deviceId, true);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.isProximity_);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_AxisBegin_004
 * @tc.desc: Test axis begin state switch multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_AxisBegin_004, TestSize.Level1)
{
    const int32_t deviceId { 40 };
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, true);
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, false);
    DeviceStateManager::GetInstance()->SetAxisBegin(deviceId, true);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_TRUE(iter->second.isAxisBegin_);
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}

/**
 * @tc.name: DeviceStateManagerTest_EnableCallback_001
 * @tc.desc: Test enable callback immediate execution
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableCallback_001, TestSize.Level1)
{
    const int32_t deviceId { 41 };
    bool callbackExecuted { false };
    auto callback = [&callbackExecuted](int32_t id) -> int32_t {
        callbackExecuted = true;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);
    EXPECT_TRUE(callbackExecuted);
}

/**
 * @tc.name: DeviceStateManagerTest_EnableCallback_002
 * @tc.desc: Test enable callback deferred execution
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStateManagerTest, DeviceStateManagerTest_EnableCallback_002, TestSize.Level1)
{
    const int32_t deviceId { 42 };
    std::set<int32_t> touches { 1 };
    DeviceStateManager::GetInstance()->AddTouches(deviceId, touches);

    bool callbackExecuted { false };
    auto callback = [&callbackExecuted](int32_t id) -> int32_t {
        callbackExecuted = true;
        return RET_OK;
    };

    DeviceStateManager::GetInstance()->EnableDevice(deviceId, callback);

    const auto &deviceStates = DeviceStateManager::GetInstance()->deviceStates_;
    auto iter = deviceStates.find(deviceId);
    EXPECT_TRUE(iter != deviceStates.cend());
    if (iter != deviceStates.cend()) {
        EXPECT_EQ(iter->second.touches_.size(), touches.size());
        EXPECT_TRUE(iter->second.HaveActiveOperations());
    }

    EXPECT_FALSE(callbackExecuted);
    DeviceStateManager::GetInstance()->OnDeviceRemoved(deviceId);
}
} // namespace MMI
} // namespace OHOS
