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

#include "libinput-private.h"

#include "input_device_manager.h"
#include "key_auto_repeat.h"
#include "mmi_log.h"
#include "uds_server.h"
#include "uds_session.h"
#include "cJSON.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t MIN_VIRTUAL_INPUT_DEVICE_ID { 1000 };
constexpr int32_t UINPUT_INPUT_DEVICE_ID { -1 };
constexpr int32_t LOC_INPUT_DEVICE_ID { 1 };
} // namespace

class InputDeviceManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MockUDSSession : public UDSSession {
public:
    MOCK_METHOD1(SendMsg, int32_t(NetPacket &));
    MockUDSSession(const std::string &programName, const int32_t moduleType, const int32_t fd, const int32_t uid,
        const int32_t pid) : UDSSession(programName, moduleType, fd, uid, pid) {}
};

class MockInputDevice {
public:
    MOCK_METHOD1(SetId, void(int32_t deviceId));
    MOCK_METHOD0(MakeVirtualDeviceInfo, int());
};

/**
 * @tc.name: InputDeviceManagerTest_GetInputDeviceIds_003
 * @tc.desc: Test the function GetInputDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetInputDeviceIds_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo info1;
    info1.networkIdOrigin = "device1";
    info1.enable = true;
    INPUT_DEV_MGR->inputDevice_[1] = info1;
    InputDeviceManager::InputDeviceInfo info2;
    info2.networkIdOrigin = "device2";
    info2.enable = false;
    INPUT_DEV_MGR->inputDevice_[2] = info2;
    InputDeviceManager::InputDeviceInfo info3;
    info3.networkIdOrigin = "device3";
    info3.enable = true;
    INPUT_DEV_MGR->inputDevice_[3] = info3;
    auto ids = INPUT_DEV_MGR->GetInputDeviceIds();
    ASSERT_EQ(ids.size(), 3);
    EXPECT_EQ(ids[0], 1);
    EXPECT_EQ(ids[1], 2);
}

/**
 * @tc.name: InputDeviceManagerTest_SupportKeys_003
 * @tc.desc: Test the function SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SupportKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo info;
    info.networkIdOrigin = "device1";
    info.enable = true;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    std::vector<int32_t> keyCodes = {1};
    std::vector<bool> keystroke;
    int32_t ret = INPUT_DEV_MGR->SupportKeys(1, keyCodes, keystroke);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(keystroke.size(), 1);
    EXPECT_EQ(keystroke[0], true);
}

/**
 * @tc.name: InputDeviceManagerTest_GetDeviceConfig_003
 * @tc.desc: Test the function GetDeviceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetDeviceConfig_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyboardType;
    int32_t ret = INPUT_DEV_MGR->GetDeviceConfig(-1, keyboardType);
    ASSERT_EQ(ret, false);
    InputDeviceManager::InputDeviceInfo info;
    info.networkIdOrigin = "device1";
    INPUT_DEV_MGR->inputDevice_[1] = info;
    ret = INPUT_DEV_MGR->GetDeviceConfig(1, keyboardType);
    ASSERT_EQ(ret, false);
    std::map<int32_t, DeviceConfig> deviceConfig;
    DeviceConfig config;
    config.keyboardType = 1;
    deviceConfig[1] = config;
    ret = INPUT_DEV_MGR->GetDeviceConfig(1, keyboardType);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(keyboardType, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_NotifyDevRemoveCallback_002
 * @tc.desc: Test the function NotifyDevRemoveCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_NotifyDevRemoveCallback_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.sysUid = "";
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevRemoveCallback(deviceId, deviceInfo));
}

/**
 * @tc.name: InputDeviceManagerTest_GenerateVirtualDeviceId_001
 * @tc.desc: Test the function GenerateVirtualDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GenerateVirtualDeviceId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 0;
    int32_t MAX_VIRTUAL_INPUT_DEVICE_NUM = 128;
    for (int i = 0; i < MAX_VIRTUAL_INPUT_DEVICE_NUM; i++) {
        INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(i, std::make_shared<InputDevice>()));
    }
    EXPECT_EQ(INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId), RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_GenerateVirtualDeviceId_002
 * @tc.desc: Test the function GenerateVirtualDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GenerateVirtualDeviceId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 0;
    INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId), RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_GenerateVirtualDeviceId_003
 * @tc.desc: Test the function GenerateVirtualDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GenerateVirtualDeviceId_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 0;
    EXPECT_EQ(INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId), RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_RemoveVirtualInputDevice_001
 * @tc.desc: Test the function RemoveVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RemoveVirtualInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    EXPECT_EQ(INPUT_DEV_MGR->RemoveVirtualInputDevice(deviceId), RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_RemoveVirtualInputDevice_002
 * @tc.desc: Test the function RemoveVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RemoveVirtualInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = std::make_shared<InputDevice>();
    EXPECT_EQ(INPUT_DEV_MGR->RemoveVirtualInputDevice(deviceId), RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_RemoveVirtualInputDevice_003
 * @tc.desc: Test the function RemoveVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RemoveVirtualInputDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    auto device = std::make_shared<InputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;
    EXPECT_EQ(INPUT_DEV_MGR->RemoveVirtualInputDevice(deviceId), RET_OK);
    EXPECT_EQ(INPUT_DEV_MGR->virtualInputDevices_.find(deviceId), INPUT_DEV_MGR->virtualInputDevices_.end());
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDevice_001
 * @tc.desc: Test the function AddVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    int32_t deviceId = 0;
    std::shared_ptr<InputDevice> device;
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = INPUT_DEV_MGR->AddVirtualInputDevice(device, deviceId);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_EQ(deviceId, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDevice_002
 * @tc.desc: Test the function AddVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    int32_t deviceId = 1;
    std::shared_ptr<InputDevice> device;
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = INPUT_DEV_MGR->AddVirtualInputDevice(device, deviceId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDevice_003
 * @tc.desc: Test the function AddVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    int32_t deviceId = 1;
    std::shared_ptr<InputDevice> device;
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_OK));
    int32_t ret = INPUT_DEV_MGR->AddVirtualInputDevice(device, deviceId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDevice_004
 * @tc.desc: Test the function AddVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDevice_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    std::shared_ptr<InputDevice> device;

    int32_t MAX_VIRTUAL_INPUT_DEVICE_NUM = 128;
    for (int i = 0; i < MAX_VIRTUAL_INPUT_DEVICE_NUM; i++) {
        INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(i, std::make_shared<InputDevice>()));
    }

    EXPECT_EQ(INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId), RET_ERR);
    int32_t ret = INPUT_DEV_MGR->AddVirtualInputDevice(device, deviceId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDevice_005
 * @tc.desc: Test the function AddVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDevice_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    std::shared_ptr<InputDevice> device;
    INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId), RET_ERR);

    int32_t ret = INPUT_DEV_MGR->AddVirtualInputDevice(device, deviceId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDevice_006
 * @tc.desc: Test the function AddVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDevice_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    std::shared_ptr<InputDevice> device;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId), RET_ERR);
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_ERR));

    int32_t ret = INPUT_DEV_MGR->AddVirtualInputDevice(device, deviceId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDevice_007
 * @tc.desc: Test the function AddVirtualInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDevice_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    std::shared_ptr<InputDevice> device;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId), RET_ERR);
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_OK));

    int32_t ret = INPUT_DEV_MGR->AddVirtualInputDevice(device, deviceId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardType_003
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 0;
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(deviceId, device));
    EXPECT_EQ(INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_NONE);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardType_004
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    int32_t keyboardType = 0;
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_.insert(std::make_pair(deviceId, device));
    EXPECT_EQ(INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_NONE);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardType_005
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardType_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    int32_t keyboardType = 0;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, InputDeviceManager::InputDeviceInfo()));
    INPUT_DEV_MGR->inputDevice_[deviceId].enable = false;
    EXPECT_EQ(INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType), RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardType_006
 * @tc.desc: Test the function GetKeyboardType with virtual device id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardType_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1000;
    int32_t keyboardType = 0;
    auto inputDevice = std::make_shared<InputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = inputDevice;
    EXPECT_EQ(INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_NONE);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardType_007
 * @tc.desc: Test the function GetKeyboardType with touchscreen id without virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardType_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;
    info.enable = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, info));
    int32_t keyboardType = 0;
    EXPECT_EQ(INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType), RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardType_008
 * @tc.desc: Test the function GetKeyboardType with touchscreen id with virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardType_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;
    info.enable = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, info));
    int32_t keyboardType = 0;

    int32_t deviceId1 = 1000;
    auto device1 = std::make_shared<InputDevice>();
    device1->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId1] = device1;

    int32_t deviceId2 = 1001;
    auto device2 = std::make_shared<InputDevice>();
    device2->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId2] = device2;

    EXPECT_EQ(INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType), RET_OK);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_ALPHABETICKEYBOARD);
#else // OHOS_BUILD_ENABLE_VKEYBOARD
    EXPECT_NE(keyboardType, KEYBOARD_TYPE_UNKNOWN);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice_Test_001
 * @tc.desc: Test the function OnEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    int32_t keyboardType = KEYBOARD_TYPE_NONE;
    EXPECT_TRUE(keyboardType != KEYBOARD_TYPE_ALPHABETICKEYBOARD);
    int32_t ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice_Test_02
 * @tc.desc: Test the function OnEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice_Test_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = true;
    deviceInfo.enable = false;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));

    int32_t ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice_Test_03
 * @tc.desc: Test the function OnEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice_Test_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));

    int32_t ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice_Test_04
 * @tc.desc: Test the function OnEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice_Test_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = false;
    deviceInfo.isPointerDevice = false;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    
    int32_t ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice_Test_05
 * @tc.desc: Test the function OnEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice_Test_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = false;
    deviceInfo.isPointerDevice = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    
    int32_t ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice_Test_06
 * @tc.desc: Test the function OnEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice_Test_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = true;
    deviceInfo.isPointerDevice = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    
    int32_t ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardDevice_Test_001
 * @tc.desc: Test the function GetKeyboardDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device *device = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);

    bool ret1 = INPUT_DEV_MGR->IsMatchKeys(device, keyCodes);
    EXPECT_FALSE(ret1);
    auto ret2 = INPUT_DEV_MGR->GetKeyboardDevice();
    EXPECT_EQ(ret2, nullptr);
}

/**
 * @tc.name: InputDeviceManagerTest_OnInputDeviceAdded_Test_001
 * @tc.desc: Test the function OnInputDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnInputDeviceAdded_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId;
    struct libinput_device *device = nullptr;
    deviceId = 2;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnInputDeviceAdded(device));
}

/**
 * @tc.name: InputDeviceManagerTest_GetDeviceSupportKey_Test_001
 * @tc.desc: Test the function GetDeviceSupportKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetDeviceSupportKey_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> keyCodes;
    int32_t deviceId = 1;
    int32_t keyboardType = KEYBOARD_TYPE_REMOTECONTROL;
    std::map<int32_t, bool> determineKbType;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_HOME);
    keyCodes.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    keyCodes.push_back(KeyEvent::KEYCODE_F2);

    int32_t ret1 = INPUT_DEV_MGR->GetKeyboardBusMode(deviceId);
    EXPECT_EQ(ret1, RET_ERR);
    int32_t ret2 = INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: GetInputDevice_Test_001
 * @tc.desc: Test the function GetInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetInputDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDeviceManager{nullptr};
    int32_t id = 1;
    bool checked = true;
    inputDeviceManager = INPUT_DEV_MGR->GetInputDevice(id, checked);
    EXPECT_NE(inputDeviceManager, nullptr);
}

/**
 * @tc.name: GetInputDeviceIds_Test_001
 * @tc.desc: Test the function GetInputDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetInputDeviceIds_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->GetInputDeviceIds());
}

/**
 * @tc.name: SupportKeys_Test_001
 * @tc.desc: Test the function SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, SupportKeys_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    std::vector<int32_t> keyCodes{12};
    std::vector<bool> keystroke{true};
    int32_t ret = INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystroke);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetDeviceConfig_Test_001
 * @tc.desc: Test the function GetDeviceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetDeviceConfig_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    bool ret = INPUT_DEV_MGR->GetDeviceConfig(deviceId, keyboardType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetDeviceSupportKey_Test_001
 * @tc.desc: Test the function GetDeviceSupportKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetDeviceSupportKey_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t ret = INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetKeyboardType_Test_001
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetKeyboardType_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t ret = INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: HasTouchDevice_Test_001
 * @tc.desc: Test the function HasTouchDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, HasTouchDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = INPUT_DEV_MGR->HasTouchDevice();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ScanPointerDevice_Test_001
 * @tc.desc: Test the function ScanPointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, ScanPointerDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->ScanPointerDevice());
}

/**
 * @tc.name: Dump_Test_001
 * @tc.desc: Test the function Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, Dump_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t fd = 1;
    std::vector<std::string> args{"test"};
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Dump(fd, args));
}

/**
 * @tc.name: DumpDeviceList_Test_001
 * @tc.desc: Test the function DumpDeviceList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, DumpDeviceList_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t fd = 1;
    std::vector<std::string> args{"test"};
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->DumpDeviceList(fd, args));
}

/**
 * @tc.name: GetVendorConfig_Test_001
 * @tc.desc: Test the function GetVendorConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetVendorConfig_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->GetVendorConfig(deviceId));
}

/**
 * @tc.name: OnEnableInputDevice_Test_001
 * @tc.desc: Test the function OnEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, OnEnableInputDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    int32_t ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
    enable = false;
    ret = INPUT_DEV_MGR->OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InitSessionLostCallback_Test_001
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InitSessionLostCallback_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->InitSessionLostCallback());
}

/**
 * @tc.name: InitSessionLostCallback_Test_002
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InitSessionLostCallback_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    INPUT_DEV_MGR->sessionLostCallbackInitialized_ = true;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->InitSessionLostCallback());
}

/**
 * @tc.name: InitSessionLostCallback_Test_003
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InitSessionLostCallback_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    INPUT_DEV_MGR->sessionLostCallbackInitialized_ = false;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->InitSessionLostCallback());
    EXPECT_FALSE(INPUT_DEV_MGR->sessionLostCallbackInitialized_);
}

/**
 * @tc.name: OnSessionLost_Test_001
 * @tc.desc: Test the function OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, OnSessionLost_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> session = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    ASSERT_NE(session, nullptr);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnSessionLost(session));
    session = nullptr;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnSessionLost(session));
}


/**
 * @tc.name: NotifyMessage_Test_001
 * @tc.desc: Test the function NotifyMessage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyMessage_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(true));
    int32_t result = INPUT_DEV_MGR->NotifyMessage(mockSession, 1, "type");
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: NotifyMessage_Test_002
 * @tc.desc: Test the function NotifyMessage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyMessage_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(false));
    int32_t result = INPUT_DEV_MGR->NotifyMessage(mockSession, 1, "type");
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: NotifyMessage_Test_003
 * @tc.desc: Test the function NotifyMessage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, NotifyMessage_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(false));
    SessionPtr nullSession = nullptr;
    int32_t result = INPUT_DEV_MGR->NotifyMessage(nullSession, 1, "type");
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: GetInputDevice_Test_002
 * @tc.desc: Test the function GetInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetInputDevice_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    int32_t id = -1;
    bool checked = true;
    std::shared_ptr inputDeviceManager = INPUT_DEV_MGR->GetInputDevice(id, checked);
    EXPECT_EQ(inputDeviceManager, nullptr);
    id = 1;
    checked = false;
    inputDeviceManager = INPUT_DEV_MGR->GetInputDevice(id, checked);
    EXPECT_NE(inputDeviceManager, nullptr);
    id = -1;
    checked = false;
    inputDeviceManager = INPUT_DEV_MGR->GetInputDevice(id, checked);
    EXPECT_EQ(inputDeviceManager, nullptr);
}

/**
 * @tc.name: GetInputDeviceIds_Test_002
 * @tc.desc: Test the function GetInputDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetInputDeviceIds_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> expectedIds = {1, 2, 3};
    std::vector<int32_t> actualIds = INPUT_DEV_MGR->GetInputDeviceIds();
    ASSERT_NE(expectedIds, actualIds);
}

/**
 * @tc.name: SupportKeys_Test_002
 * @tc.desc: Test the function SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, SupportKeys_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t COMMON_PARAMETER_ERROR = 401;
    std::vector<int32_t> keyCodes = {1, 2, 3};
    std::vector<bool> keystrokes{true};
    int32_t ret = INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_NE(keystrokes.size(), keyCodes.size());
    EXPECT_TRUE(keystrokes[0]);
    EXPECT_FALSE(keystrokes[1]);
    EXPECT_FALSE(keystrokes[2]);
    deviceId = -1;
    keyCodes = {1, 2, 3};
    ret = INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_FALSE(keystrokes.empty());
    deviceId = 100;
    keyCodes = {1, 2, 3};
    ret = INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_FALSE(keystrokes.empty());
    deviceId = 1;
    keyCodes.clear();
    keystrokes.clear();
    ret = INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_TRUE(keystrokes.empty());
}

/**
 * @tc.name: GetDeviceConfig_Test_002
 * @tc.desc: Test the function GetDeviceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetDeviceConfig_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = -1;
    int32_t keyboardType = 5;
    bool ret = INPUT_DEV_MGR->GetDeviceConfig(deviceId, keyboardType);
    EXPECT_FALSE(ret);
    deviceId = 10;
    keyboardType = -3;
    ret = INPUT_DEV_MGR->GetDeviceConfig(deviceId, keyboardType);
    EXPECT_FALSE(ret);
    deviceId = -8;
    keyboardType = -10;
    ret = INPUT_DEV_MGR->GetDeviceConfig(deviceId, keyboardType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetKeyboardBusMode_Test_002
 * @tc.desc: Test the function GetKeyboardBusMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetKeyboardBusMode_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t ret = INPUT_DEV_MGR->GetKeyboardBusMode(deviceId);
    EXPECT_NE(ret, 0);
    deviceId = 0;
    ret = INPUT_DEV_MGR->GetKeyboardBusMode(deviceId);
    EXPECT_NE(ret, 0);
    deviceId = -5;
    ret = INPUT_DEV_MGR->GetKeyboardBusMode(deviceId);
    EXPECT_NE(ret, 0);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetDeviceSupportKey_Test_002
 * @tc.desc: Test the function GetDeviceSupportKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetDeviceSupportKey_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = -5;
    int32_t returnCode = 401;
    int32_t ret = INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret, RET_ERR);
    deviceId = -1;
    keyboardType = 2;
    ret = INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
    deviceId = -1;
    keyboardType = -2;
    ret = INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: GetKeyboardType_Test_002
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetKeyboardType_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = -100;
    int32_t returnCode = 401;
    int32_t ret = INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, RET_OK);
    deviceId = -1;
    keyboardType = 1;
    ret = INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
    deviceId = -10;
    keyboardType = -5;
    ret = INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: SetInputStatusChangeCallback_Test_001
 * @tc.desc: Test the function SetInputStatusChangeCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, SetInputStatusChangeCallback_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    using InputDeviceCallback = std::function<void(int, std::string, std::string, std::string)>;
    InputDeviceCallback callback =
        [] (int status, std::string nodeName, const std::string& deviceName, const std::string& deviceId) {};
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->SetInputStatusChangeCallback(callback));
}

/**
 * @tc.name: AddDevListener_Test_001
 * @tc.desc: Test the function AddDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, AddDevListener_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->AddDevListener(session));
}

/**
 * @tc.name: RemoveDevListener_Test_001
 * @tc.desc: Test the function RemoveDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, RemoveDevListener_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->RemoveDevListener(session));
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: HasPointerDevice_Test_001
 * @tc.desc: Test the function HasPointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, HasPointerDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = INPUT_DEV_MGR->HasPointerDevice();
    EXPECT_FALSE(ret);
    ret = INPUT_DEV_MGR->HasTouchDevice();
    EXPECT_FALSE(ret);
}

#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

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
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevCallback(deviceId, inDevice));
}

/**
 * @tc.name: OnInputDeviceAdded_Test_001
 * @tc.desc: Test the function OnInputDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, OnInputDeviceAdded_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_device* inputDevices = nullptr;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnInputDeviceAdded(inputDevices));
}

/**
 * @tc.name: OnInputDeviceRemoved_Test_001
 * @tc.desc: Test the function OnInputDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, OnInputDeviceRemoved_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_device* inputDevices = nullptr;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnInputDeviceRemoved(inputDevices));
}

/**
 * @tc.name: InputDeviceManagerTest_IsRemote
 * @tc.desc: Test Cover the else branch of if (device != inputDevice_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsRemote, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = 30;
    ASSERT_FALSE(INPUT_DEV_MGR->IsRemote(id));
}

/**
 * @tc.name: InputDeviceManagerTest_IsRemote_001
 * @tc.desc: Test Cover the if (device != inputDevice_.end()) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsRemote_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inputDeviceInfo;
    int32_t id = 30;
    inputDeviceInfo.isRemote = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(id, inputDeviceInfo));
    ASSERT_TRUE(INPUT_DEV_MGR->IsRemote(id));
}

/**
 * @tc.name: InputDeviceManagerTest_NotifyDevCallback
 * @tc.desc: Test Cover the if (!inDevice.isTouchableDevice || (deviceId < 0)) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_NotifyDevCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceid = -1;
    inDevice.isTouchableDevice = false;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevCallback(deviceid, inDevice));
    inDevice.isTouchableDevice = true;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevCallback(deviceid, inDevice));
}

/**
 * @tc.name: InputDeviceManagerTest_NotifyDevCallback_001
 * @tc.desc: Test Cover the if (!inDevice.sysUid.empty()) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_NotifyDevCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceid = 1;
    inDevice.isTouchableDevice = true;
    inDevice.sysUid = "123456";
    using inputDeviceCallback =
        std::function<void(int32_t deviceId, std::string nodeName, std::string devName, std::string devStatus)>;
    inputDeviceCallback callback =
        [] (int32_t deviceId, std::string nodeName, std::string devName, std::string devStatus) {};
    INPUT_DEV_MGR->SetInputStatusChangeCallback(callback);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevCallback(deviceid, inDevice));
    inDevice.sysUid.clear();
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDevCallback(deviceid, inDevice));
}

/**
 * @tc.name: InputDeviceManagerTest_ScanPointerDevice
 * @tc.desc: Test Cover the if (it->second.isPointerDevice && it->second.enable) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ScanPointerDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 10;
    inDevice.isPointerDevice = false;
    inDevice.enable = false;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    deviceId = 15;
    inDevice.isPointerDevice = true;
    inDevice.enable = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->ScanPointerDevice());
}

/**
 * @tc.name: InputDeviceManagerTest_ScanPointerDevice_001
 * @tc.desc: Test Cover the if (!hasPointerDevice) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ScanPointerDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 10;
    inDevice.isPointerDevice = false;
    inDevice.enable = false;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->ScanPointerDevice());
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice
 * @tc.desc: Test Cover the if (enable) and if (keyboardType != KEYBOARD_TYPE_ALPHABETICKEYBOARD) and
 * <br> if (item.second.isPointerDevice && item.second.enable) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    DeviceConfig deviceConfig;
    deviceConfig.keyboardType = KEYBOARD_TYPE_NONE;
    bool enable = true;
    int32_t deviceId = 10;
    inDevice.isRemote = true;
    inDevice.enable = false;
    inDevice.isPointerDevice = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    KeyRepeat->deviceConfig_.insert(std::make_pair(deviceId, deviceConfig));
    ASSERT_EQ(INPUT_DEV_MGR->OnEnableInputDevice(enable), RET_OK);
    INPUT_DEV_MGR->inputDevice_.clear();
    KeyRepeat->deviceConfig_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_OnEnableInputDevice_001
 * @tc.desc: Test Cover the else branch of the OnEnableInputDevice function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnEnableInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    DeviceConfig deviceConfig;
    deviceConfig.keyboardType = KEYBOARD_TYPE_ALPHABETICKEYBOARD;
    bool enable = false;
    int32_t deviceId = 20;
    inDevice.isRemote = true;
    inDevice.enable = true;
    inDevice.isPointerDevice = false;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    KeyRepeat->deviceConfig_.insert(std::make_pair(deviceId, deviceConfig));
    deviceId = 30;
    inDevice.isRemote = false;
    inDevice.enable = false;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    ASSERT_EQ(INPUT_DEV_MGR->OnEnableInputDevice(enable), RET_OK);
    INPUT_DEV_MGR->inputDevice_.clear();
    KeyRepeat->deviceConfig_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_GetTouchPadIds_001
 * @tc.desc: Test GetTouchPadIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetTouchPadIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 5;
    inDevice.isPointerDevice = false;
    inDevice.enable = false;
    inDevice.dhid = 2;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->GetTouchPadIds());
}

/**
 * @tc.name: InputDeviceManagerTest_GetTouchPadIds_002
 * @tc.desc: Test GetTouchPadIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetTouchPadIds_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 3;
    inDevice.enable = false;
    inDevice.dhid = 2;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    INPUT_DEV_MGR->inputDevice_.clear();
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->GetTouchPadIds());
}

/**
 * @tc.name: InputDeviceManagerTest_IsMatchKeys_001
 * @tc.desc: Test IsMatchKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsMatchKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device *device = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_T);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);

    bool ret1 = INPUT_DEV_MGR->IsMatchKeys(device, keyCodes);
    EXPECT_FALSE(ret1);
}

/**
 * @tc.name: InputDeviceManagerTest_OnInputDeviceAdded_Test_01
 * @tc.desc: Test the function OnInputDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnInputDeviceAdded_Test_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.inputDeviceOrigin = nullptr;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    EXPECT_TRUE(deviceInfo.inputDeviceOrigin == inputDevice);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnInputDeviceAdded(inputDevice));
}

/**
 * @tc.name: InputDeviceManagerTest_OnInputDeviceAdded_Test_02
 * @tc.desc: Test the function OnInputDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_OnInputDeviceAdded_Test_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 3;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.isPointerDevice = true;
    deviceInfo.enable = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnInputDeviceAdded(inputDevice));
}

/**
 * @tc.name: OnInputDeviceRemoved_Test_01
 * @tc.desc: Test the function OnInputDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, OnInputDeviceRemoved_Test_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.inputDeviceOrigin = nullptr;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    EXPECT_TRUE(deviceInfo.inputDeviceOrigin == inputDevice);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnInputDeviceRemoved(inputDevice));
}

/**
 * @tc.name: OnInputDeviceRemoved_Test_02
 * @tc.desc: Test the function OnInputDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, OnInputDeviceRemoved_Test_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 5;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.isPointerDevice = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));

    std::string sysUid;
    EXPECT_TRUE(sysUid.empty());
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->OnInputDeviceRemoved(inputDevice));
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardDevice_Test_01
 * @tc.desc: Test the function GetKeyboardDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardDevice_Test_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device *device = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);

    bool ret1 = INPUT_DEV_MGR->IsMatchKeys(device, keyCodes);
    EXPECT_FALSE(ret1);
    auto ret2 = INPUT_DEV_MGR->GetKeyboardDevice();
    EXPECT_EQ(ret2, nullptr);
}

/**
 * @tc.name: InputDeviceManagerTest_GetKeyboardDevice_Test_02
 * @tc.desc: Test the function GetKeyboardDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetKeyboardDevice_Test_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device *device = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    INPUT_DEV_MGR->inputDevice_.clear();
    bool ret1 = INPUT_DEV_MGR->IsMatchKeys(device, keyCodes);
    EXPECT_FALSE(ret1);
    auto ret2 = INPUT_DEV_MGR->GetKeyboardDevice();
    EXPECT_EQ(ret2, nullptr);
}

/**
 * @tc.name: InputDeviceManagerTest_GetDeviceSupportKey_Test_01
 * @tc.desc: Test the function GetDeviceSupportKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetDeviceSupportKey_Test_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> keyCodes;
    int32_t deviceId = 1;
    int32_t keyboardType = KEYBOARD_TYPE_REMOTECONTROL;
    std::vector<bool> supportKey;
    int32_t returnCode1 = 401;

    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_HOME);
    keyCodes.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    keyCodes.push_back(KeyEvent::KEYCODE_F2);

    int32_t ret = INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, supportKey);
    EXPECT_NE(ret, RET_OK);
    int32_t ret2 = INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret2, returnCode1);
}

/**
 * @tc.name: InputDeviceManagerTest_IsInputDeviceEnable_Test_01
 * @tc.desc: Test the function IsInputDeviceEnable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsInputDeviceEnable_Test_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 1000;
    bool ret = INPUT_DEV_MGR->IsInputDeviceEnable(deviceId);
    ASSERT_EQ(ret, false);
    deviceId = 5;
    inDevice.enable = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, inDevice));
    deviceId = 5;
    ret = INPUT_DEV_MGR->IsInputDeviceEnable(deviceId);
    ASSERT_EQ(ret, true);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD_EXT_FLAG
/**
 * @tc.name: InputDeviceManagerTest_KeyboardExtFlag_Verify_Json
 * @tc.desc: Test the json file format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_KeyboardExtFlag_Verify_Json, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string filePath = "/system/etc/multimodalinput/keyboard_ext_flag.json";
    std::ifstream file(filePath);
    EXPECT_TRUE(file.is_open());
    std::string jsonContent = ReadJsonFile(filePath);
    EXPECT_FALSE(jsonContent.empty());
    cJSON *root = cJSON_Parse(jsonContent.c_str());
    EXPECT_NE(root, nullptr);
    cJSON *keyboardExtFlag = cJSON_GetObjectItem(root, "keyboardExtFlag");
    EXPECT_NE(keyboardExtFlag, nullptr);
    EXPECT_EQ(keyboardExtFlag->type, cJSON_Array);
    cJSON *item = nullptr;
    cJSON *vendor = nullptr;
    cJSON *product = nullptr;
    cJSON *extFlag = nullptr;
    cJSON_ArrayForEach(item, keyboardExtFlag)
    {
        vendor = cJSON_GetObjectItem(item, "vendor");
        EXPECT_NE(vendor, nullptr);
        EXPECT_EQ(vendor->type, cJSON_Number);
        product = cJSON_GetObjectItem(item, "product");
        EXPECT_NE(product, nullptr);
        EXPECT_EQ(product->type, cJSON_Number);
        extFlag = cJSON_GetObjectItem(item, "extFlag");
        EXPECT_NE(extFlag, nullptr);
        EXPECT_EQ(extFlag->type, cJSON_Number);
    }
    cJSON_Delete(root);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD_EXT_FLAG

/**
 * @tc.name: InputDeviceManagerTest_IsLocalDevice_Test_01
 * @tc.desc: Test the function IsLocalDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsLocalDevice_Test_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo info;
    info.networkIdOrigin = "local_device";
    INPUT_DEV_MGR->AddPhysicalInputDeviceInner(LOC_INPUT_DEVICE_ID, info);
    bool isLocalDevice = INPUT_DEV_MGR->IsLocalDevice(LOC_INPUT_DEVICE_ID);
    ASSERT_EQ(isLocalDevice, true);

    isLocalDevice = INPUT_DEV_MGR->IsLocalDevice(UINPUT_INPUT_DEVICE_ID);
    ASSERT_EQ(isLocalDevice, false);

    isLocalDevice = INPUT_DEV_MGR->IsLocalDevice(MIN_VIRTUAL_INPUT_DEVICE_ID);
    ASSERT_EQ(isLocalDevice, false);
}

/**
 * @tc.name: InputDeviceManagerTest_GetTouchscreenKeyboardType_001
 * @tc.desc: Test the function GetTouchscreenKeyboardType, non-touchscreen case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetTouchscreenKeyboardType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = false;
    int32_t keyboardType = 0;
    EXPECT_EQ(INPUT_DEV_MGR->GetTouchscreenKeyboardType(info, keyboardType), RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_GetTouchscreenKeyboardType_002
 * @tc.desc: Test the function GetTouchscreenKeyboardType, touchscreen with no virtual devices.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetTouchscreenKeyboardType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;
    int32_t keyboardType = 0;
    EXPECT_EQ(INPUT_DEV_MGR->GetTouchscreenKeyboardType(info, keyboardType), RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_GetTouchscreenKeyboardType_003
 * @tc.desc: Test the function GetTouchscreenKeyboardType, touchscreen with floating keyboard.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetTouchscreenKeyboardType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;
    int32_t keyboardType = 0;

    int32_t deviceId = 1;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;

    EXPECT_EQ(INPUT_DEV_MGR->GetTouchscreenKeyboardType(info, keyboardType), RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_GetTouchscreenKeyboardType_004
 * @tc.desc: Test the function GetTouchscreenKeyboardType, touchscreen with full keyboard.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetTouchscreenKeyboardType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;
    int32_t keyboardType = 0;

    int32_t deviceId = 1;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;

    int32_t deviceId2 = 2;
    auto device2 = std::make_shared<InputDevice>();
    device2->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId2] = device2;

    EXPECT_EQ(INPUT_DEV_MGR->GetTouchscreenKeyboardType(info, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_ALPHABETICKEYBOARD);
}

/**
 * @tc.name: InputDeviceManagerTest_GetVirtualKeyboardType_001
 * @tc.desc: Test the function GetVirtualKeyboardType with empty virtual device list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetVirtualKeyboardType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 0;
    EXPECT_EQ(INPUT_DEV_MGR->GetVirtualKeyboardType(deviceId, keyboardType), RET_OK);
}

/**
 * @tc.name: InputDeviceManagerTest_GetVirtualKeyboardType_002
 * @tc.desc: Test the function GetVirtualKeyboardType with non-keyboard virtual device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetVirtualKeyboardType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 0;
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = std::make_shared<InputDevice>();
    EXPECT_EQ(INPUT_DEV_MGR->GetVirtualKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_NONE);
}

/**
 * @tc.name: InputDeviceManagerTest_GetVirtualKeyboardType_003
 * @tc.desc: Test the function GetVirtualKeyboardType with floating virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetVirtualKeyboardType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 0;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;
    EXPECT_EQ(INPUT_DEV_MGR->GetVirtualKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_ALPHABETICKEYBOARD);
}

/**
 * @tc.name: InputDeviceManagerTest_GetVirtualKeyboardType_004
 * @tc.desc: Test the function GetVirtualKeyboardType with full virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetVirtualKeyboardType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t keyboardType = 0;
    auto device1 = std::make_shared<InputDevice>();
    device1->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device1;

    int32_t deviceId2 = 2;
    int32_t keyboardType2 = 0;
    auto device2 = std::make_shared<InputDevice>();
    device2->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId2] = device2;
    EXPECT_EQ(INPUT_DEV_MGR->GetVirtualKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_ALPHABETICKEYBOARD);

    EXPECT_EQ(INPUT_DEV_MGR->GetVirtualKeyboardType(deviceId2, keyboardType2), RET_OK);
    EXPECT_EQ(keyboardType2, KEYBOARD_TYPE_NONE);
}

/**
 * @tc.name: InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_001
 * @tc.desc: Test the function FillInputDeviceWithVirtualCapability with non-touchscreen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDevice = std::make_shared<InputDevice>();
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = false;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->FillInputDeviceWithVirtualCapability(inputDevice, info));
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD), false);
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER), false);
}

/**
 * @tc.name: InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_002
 * @tc.desc: Test the function FillInputDeviceWithVirtualCapability with touchscreen but no virtual devices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDevice = std::make_shared<InputDevice>();
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->FillInputDeviceWithVirtualCapability(inputDevice, info));
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD), true);
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER), true);
}

/**
 * @tc.name: InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_003
 * @tc.desc: Test the function FillInputDeviceWithVirtualCapability with touchscreen and floating virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDevice = std::make_shared<InputDevice>();
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;

    int32_t deviceId2 = 2;
    auto device2 = std::make_shared<InputDevice>();
    device2->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId2] = device2;

    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->FillInputDeviceWithVirtualCapability(inputDevice, info));
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD), true);
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER), true);
}

/**
 * @tc.name: InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_004
 * @tc.desc: Test the function FillInputDeviceWithVirtualCapability with touchscreen and virtual trackpad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDevice = std::make_shared<InputDevice>();
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;

    int32_t deviceId2 = 2;
    auto device2 = std::make_shared<InputDevice>();
    device2->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId2] = device2;

    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->FillInputDeviceWithVirtualCapability(inputDevice, info));
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD), true);
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER), true);
}

/**
 * @tc.name: InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_005
 * @tc.desc: Test the function FillInputDeviceWithVirtualCapability with touchscreen and full virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FillInputDeviceWithVirtualCapability_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDevice = std::make_shared<InputDevice>();
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;

    int32_t deviceId2 = 2;
    auto device2 = std::make_shared<InputDevice>();
    device2->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId2] = device2;

    int32_t deviceId3 = 3;
    auto device3 = std::make_shared<InputDevice>();
    device3->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId3] = device3;

    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->FillInputDeviceWithVirtualCapability(inputDevice, info));
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD), true);
    EXPECT_EQ(inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER), true);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDeviceInner_NoVkb_001
 * @tc.desc: Test the function AddVirtualInputDeviceInner without virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDeviceInner_NoVkb_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    INPUT_DEV_MGR->virtualKeyboardEverConnected_ = false;
    INPUT_DEV_MGR->virtualInputDevices_.clear();

    int32_t deviceId = 1;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->AddVirtualInputDeviceInner(deviceId, device));
    EXPECT_EQ(INPUT_DEV_MGR->virtualKeyboardEverConnected_, false);
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDeviceInner_Vkb_002
 * @tc.desc: Test the function AddVirtualInputDeviceInner with virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDeviceInner_Vkb_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    INPUT_DEV_MGR->virtualKeyboardEverConnected_ = false;
    INPUT_DEV_MGR->virtualInputDevices_.clear();

    int32_t deviceId = 1;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->AddVirtualInputDeviceInner(deviceId, device));
    EXPECT_EQ(INPUT_DEV_MGR->virtualInputDevices_[deviceId], device);
    EXPECT_EQ(INPUT_DEV_MGR->virtualKeyboardEverConnected_, true);
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
/**
 * @tc.name: InputDeviceManagerTest_IsVirtualKeyboardDeviceEverConnected_NoVkb_001
 * @tc.desc: Test the function IsVirtualKeyboardDeviceEverConnected without virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsVirtualKeyboardDeviceEverConnected_NoVkb_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    INPUT_DEV_MGR->virtualKeyboardEverConnected_ = false;
    EXPECT_EQ(INPUT_DEV_MGR->IsVirtualKeyboardDeviceEverConnected(), false);
}

/**
 * @tc.name: InputDeviceManagerTest_IsVirtualKeyboardDeviceEverConnected_Vkb_002
 * @tc.desc: Test the function IsVirtualKeyboardDeviceEverConnected with virtual keyboard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsVirtualKeyboardDeviceEverConnected_Vkb_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    INPUT_DEV_MGR->virtualKeyboardEverConnected_ = true;
    EXPECT_EQ(INPUT_DEV_MGR->IsVirtualKeyboardDeviceEverConnected(), true);
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

/**
 * @tc.name: InputDeviceManagerTest_SetIsDeviceReportEvent_001
 * @tc.desc: Test the function SetIsDeviceReportEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetIsDeviceReportEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo info;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, info));
    INPUT_DEV_MGR->SetIsDeviceReportEvent(deviceId, false);
    EXPECT_EQ(INPUT_DEV_MGR->inputDevice_[deviceId].isDeviceReportEvent, false);
}

/**
 * @tc.name: InputDeviceManagerTest_GetIsDeviceReportEvent_001
 * @tc.desc: Test the function GetIsDeviceReportEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetIsDeviceReportEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo info;
    info.isDeviceReportEvent = true;
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, info));
    EXPECT_EQ(INPUT_DEV_MGR->GetIsDeviceReportEvent(deviceId), false);
}

/**
 * @tc.name: InputDeviceManagerTest_GetInputDevice_001
 * @tc.desc: Test GetInputDevice with virtual device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1000;
    bool checked = true;
    auto device = std::make_shared<InputDevice>();
    device->SetName("VirtualDevice");
    device->SetId(deviceId);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;
    
    auto result = INPUT_DEV_MGR->GetInputDevice(deviceId, checked);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetId(), deviceId);
    
    INPUT_DEV_MGR->virtualInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_GetInputDevice_002
 * @tc.desc: Test GetInputDevice with non-existent device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 999;
    bool checked = true;
    
    auto result = INPUT_DEV_MGR->GetInputDevice(deviceId, checked);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: InputDeviceManagerTest_GetInputDevice_003
 * @tc.desc: Test GetInputDevice with checked flag false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetInputDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    bool checked = false;
    
    InputDeviceManager::InputDeviceInfo info;
    info.enable = false;
    info.isLocal = true;
    INPUT_DEV_MGR->inputDevice_[deviceId] = info;
    
    auto result = INPUT_DEV_MGR->GetInputDevice(deviceId, checked);
    ASSERT_NE(result, nullptr);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_GetLibinputDevice_001
 * @tc.desc: Test GetLibinputDevice with existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetLibinputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    
    InputDeviceManager::InputDeviceInfo info;
    libinput_device* libinputDev = reinterpret_cast<libinput_device*>(0x12345678);
    info.inputDeviceOrigin = libinputDev;
    INPUT_DEV_MGR->inputDevice_[deviceId] = info;
    
    auto result = INPUT_DEV_MGR->GetLibinputDevice(deviceId);
    EXPECT_EQ(result, libinputDev);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_GetLibinputDevice_002
 * @tc.desc: Test GetLibinputDevice with non-existent device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetLibinputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 999;
    
    auto result = INPUT_DEV_MGR->GetLibinputDevice(deviceId);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: InputDeviceManagerTest_FillInputDevice_001
 * @tc.desc: Test FillInputDevice with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FillInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDevice = std::make_shared<InputDevice>();
    libinput_device* deviceOrigin = nullptr;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->FillInputDevice(inputDevice, deviceOrigin));
}

/**
 * @tc.name: InputDeviceManagerTest_GetInputDeviceIds_001
 * @tc.desc: Test GetInputDeviceIds with both physical and virtual devices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetInputDeviceIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info1;
    info1.enable = true;
    INPUT_DEV_MGR->inputDevice_[1] = info1;
    INPUT_DEV_MGR->inputDevice_[2] = info1;
    
    auto device = std::make_shared<InputDevice>();
    device->SetId(1000);
    INPUT_DEV_MGR->virtualInputDevices_[1000] = device;
    
    auto ids = INPUT_DEV_MGR->GetInputDeviceIds();
    ASSERT_EQ(ids.size(), 3);
    
    INPUT_DEV_MGR->inputDevice_.clear();
    INPUT_DEV_MGR->virtualInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_CheckDevice_001
 * @tc.desc: Test CheckDevice with null predicate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_CheckDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    
    auto result = INPUT_DEV_MGR->CheckDevice(deviceId, nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_ForDevice_001
 * @tc.desc: Test ForDevice with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ForDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->ForDevice(deviceId, nullptr));
}

/**
 * @tc.name: InputDeviceManagerTest_HiddenInputDevice_GetName_001
 * @tc.desc: Test HiddenInputDevice::GetName with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HiddenInputDevice_GetName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.inputDeviceOrigin = nullptr;
    
    InputDeviceManager::HiddenInputDevice hiddenDev(info);
    auto name = hiddenDev.GetName();
    EXPECT_EQ(name, "null");
}

/**
 * @tc.name: InputDeviceManagerTest_HiddenInputDevice_GetName_002
 * @tc.desc: Test HiddenInputDevice::GetName with valid device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HiddenInputDevice_GetName_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto device = std::make_shared<InputDevice>();
    device->SetName("TestDevice");
    InputDeviceManager::InputDeviceInfo info;
    info.inputDeviceOrigin = nullptr;
    
    InputDeviceManager::HiddenInputDevice hiddenDev(info);
    auto name = hiddenDev.GetName();
    EXPECT_EQ(name, "null");
}

/**
 * @tc.name: InputDeviceManagerTest_HiddenInputDevice_IsJoystick_001
 * @tc.desc: Test HiddenInputDevice::IsJoystick with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HiddenInputDevice_IsJoystick_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.inputDeviceOrigin = nullptr;
    
    InputDeviceManager::HiddenInputDevice hiddenDev(info);
    auto result = hiddenDev.IsJoystick();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_HiddenInputDevice_IsMouse_001
 * @tc.desc: Test HiddenInputDevice::IsMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HiddenInputDevice_IsMouse_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.isPointerDevice = true;
    
    InputDeviceManager::HiddenInputDevice hiddenDev(info);
    auto result = hiddenDev.IsMouse();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_HiddenInputDevice_IsMouse_002
 * @tc.desc: Test HiddenInputDevice::IsMouse with false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HiddenInputDevice_IsMouse_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.isPointerDevice = false;
    
    InputDeviceManager::HiddenInputDevice hiddenDev(info);
    auto result = hiddenDev.IsMouse();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_PhysicalInputDevice_GetId_001
 * @tc.desc: Test PhysicalInputDevice::GetId with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_PhysicalInputDevice_GetId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto id = InputDeviceManager::PhysicalInputDevice::GetId(nullptr);
    EXPECT_TRUE(id.empty());
}

/**
 * @tc.name: InputDeviceManagerTest_PhysicalInputDevice_AddInputDevice_001
 * @tc.desc: Test PhysicalInputDevice::AddInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_PhysicalInputDevice_AddInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::PhysicalInputDevice physDev;
    physDev.AddInputDevice(1);

    EXPECT_NE(physDev.GetInputDeviceCount(), 1);
}

/**
 * @tc.name: InputDeviceManagerTest_PhysicalInputDevice_RemoveInputDevice_001
 * @tc.desc: Test PhysicalInputDevice::RemoveInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_PhysicalInputDevice_RemoveInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::PhysicalInputDevice physDev;
    physDev.AddInputDevice(1);
    physDev.AddInputDevice(2);
    
    physDev.RemoveInputDevice(1);
    
    EXPECT_EQ(physDev.GetInputDeviceCount(), 0);
}

/**
 * @tc.name: InputDeviceManagerTest_PhysicalInputDevice_ForeachInputDevice_001
 * @tc.desc: Test PhysicalInputDevice::ForeachInputDevice with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_PhysicalInputDevice_ForeachInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::PhysicalInputDevice physDev;
    ASSERT_NO_FATAL_FAILURE(physDev.ForeachInputDevice(nullptr));
}

/**
 * @tc.name: InputDeviceManagerTest_PhysicalInputDevice_ForeachInputDevice_002
 * @tc.desc: Test PhysicalInputDevice::ForeachInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_PhysicalInputDevice_ForeachInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::PhysicalInputDevice physDev;
    physDev.AddInputDevice(1);
    physDev.AddInputDevice(2);
    
    int count = 0;
    physDev.ForeachInputDevice([&count](int32_t deviceId) {
        count++;
    });
    
    EXPECT_NE(count, 2);
}

/**
 * @tc.name: InputDeviceManagerTest_GetTouchPadDeviceOrigins_001
 * @tc.desc: Test GetTouchPadDeviceOrigins with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetTouchPadDeviceOrigins_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.inputDeviceOrigin = nullptr;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    
    auto result = INPUT_DEV_MGR->GetTouchPadDeviceOrigins();
    EXPECT_TRUE(result.empty());
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_IsPointerDevice_SharedPtr_001
 * @tc.desc: Test IsPointerDevice with shared_ptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsPointerDevice_SharedPtr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    
    auto result = INPUT_DEV_MGR->IsPointerDevice(device);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_IsPointerDevice_SharedPtr_002
 * @tc.desc: Test IsPointerDevice with shared_ptr null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsPointerDevice_SharedPtr_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::shared_ptr<InputDevice> device = nullptr;
    
    auto result = INPUT_DEV_MGR->IsPointerDevice(device);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_IsPointerDevice_SharedPtr_003
 * @tc.desc: Test IsPointerDevice with non-pointer device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsPointerDevice_SharedPtr_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    
    auto result = INPUT_DEV_MGR->IsPointerDevice(device);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_IsTouchableDevice_SharedPtr_001
 * @tc.desc: Test IsTouchableDevice with shared_ptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsTouchableDevice_SharedPtr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    
    auto result = INPUT_DEV_MGR->IsTouchableDevice(device);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_IsTouchableDevice_SharedPtr_002
 * @tc.desc: Test IsTouchableDevice with shared_ptr null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsTouchableDevice_SharedPtr_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::shared_ptr<InputDevice> device = nullptr;
    
    auto result = INPUT_DEV_MGR->IsTouchableDevice(device);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_IsKeyboardDevice_SharedPtr_001
 * @tc.desc: Test IsKeyboardDevice with shared_ptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsKeyboardDevice_SharedPtr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    
    auto result = INPUT_DEV_MGR->IsKeyboardDevice(device);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_IsKeyboardDevice_SharedPtr_002
 * @tc.desc: Test IsKeyboardDevice with shared_ptr null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_IsKeyboardDevice_SharedPtr_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::shared_ptr<InputDevice> device = nullptr;
    
    auto result = INPUT_DEV_MGR->IsKeyboardDevice(device);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_NotifyInputdeviceMessage_001
 * @tc.desc: Test NotifyInputdeviceMessage with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_NotifyInputdeviceMessage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    int32_t result = INPUT_DEV_MGR->NotifyInputdeviceMessage(nullptr, 1, 1);
    EXPECT_EQ(result, ERROR_NULL_POINTER);
}

/**
 * @tc.name: InputDeviceManagerTest_SetInputDeviceEnabled_001
 * @tc.desc: Test SetInputDeviceEnabled with invalid deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetInputDeviceEnabled_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(true));
    
    int32_t result = INPUT_DEV_MGR->SetInputDeviceEnabled(999, true, 1, pid, mockSession);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputDeviceManagerTest_SetInputDeviceEnabled_002
 * @tc.desc: Test SetInputDeviceEnabled with enable false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetInputDeviceEnabled_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(true));
    
    InputDeviceManager::InputDeviceInfo info;
    info.enable = true;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    
    int32_t result = INPUT_DEV_MGR->SetInputDeviceEnabled(1, false, 1, pid, mockSession);
    EXPECT_EQ(result, RET_OK);
    EXPECT_EQ(INPUT_DEV_MGR->inputDevice_[1].enable, false);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_RecoverInputDeviceEnabled_001
 * @tc.desc: Test RecoverInputDeviceEnabled with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RecoverInputDeviceEnabled_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->RecoverInputDeviceEnabled(nullptr));
}

/**
 * @tc.name: InputDeviceManagerTest_RecoverInputDeviceEnabled_002
 * @tc.desc: Test RecoverInputDeviceEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RecoverInputDeviceEnabled_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    
    InputDeviceManager::InputDeviceInfo info;
    info.enable = false;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    INPUT_DEV_MGR->recoverList_[1] = pid;
    
    INPUT_DEV_MGR->RecoverInputDeviceEnabled(mockSession);
    
    EXPECT_EQ(INPUT_DEV_MGR->inputDevice_[1].enable, true);
    EXPECT_TRUE(INPUT_DEV_MGR->recoverList_.empty());
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_GetMultiKeyboardDevice_001
 * @tc.desc: Test GetMultiKeyboardDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetMultiKeyboardDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::vector<libinput_device*> keyboards;
    INPUT_DEV_MGR->GetMultiKeyboardDevice(keyboards);
    
    EXPECT_TRUE(keyboards.empty());
}

/**
 * @tc.name: InputDeviceManagerTest_Attach_001
 * @tc.desc: Test Attach
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_Attach_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    class MockObserver : public IDeviceObserver {
    public:
        MOCK_METHOD1(OnDeviceAdded, void(int32_t));
        MOCK_METHOD1(OnDeviceRemoved, void(int32_t));
        MOCK_METHOD1(OnDeviceFirstReportEvent, void(int32_t));
        MOCK_METHOD3(UpdatePointerDevice, void(bool, bool, bool));
    };
    
    auto observer = std::make_shared<MockObserver>();
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Attach(observer));
}

/**
 * @tc.name: InputDeviceManagerTest_Detach_001
 * @tc.desc: Test Detach
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_Detach_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    class MockObserver : public IDeviceObserver {
    public:
        MOCK_METHOD1(OnDeviceAdded, void(int32_t));
        MOCK_METHOD1(OnDeviceRemoved, void(int32_t));
        MOCK_METHOD1(OnDeviceFirstReportEvent, void(int32_t));
        MOCK_METHOD3(UpdatePointerDevice, void(bool, bool, bool));
    };
    
    auto observer = std::make_shared<MockObserver>();
    INPUT_DEV_MGR->Attach(observer);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Detach(observer));
}

/**
 * @tc.name: InputDeviceManagerTest_NotifyPointerDevice_001
 * @tc.desc: Test NotifyPointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_NotifyPointerDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    class MockObserver : public IDeviceObserver {
    public:
        MOCK_METHOD1(OnDeviceAdded, void(int32_t));
        MOCK_METHOD1(OnDeviceRemoved, void(int32_t));
        MOCK_METHOD1(OnDeviceFirstReportEvent, void(int32_t));
        MOCK_METHOD3(UpdatePointerDevice, void(bool, bool, bool));
    };
    
    auto observer = std::make_shared<MockObserver>();
    EXPECT_CALL(*observer, UpdatePointerDevice(true, true, true));
    
    INPUT_DEV_MGR->Attach(observer);
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyPointerDevice(true, true, true));
    INPUT_DEV_MGR->Detach(observer);
}

/**
 * @tc.name: InputDeviceManagerTest_FindInputDeviceId_001
 * @tc.desc: Test FindInputDeviceId with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FindInputDeviceId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto deviceId = INPUT_DEV_MGR->FindInputDeviceId(nullptr);
    EXPECT_EQ(deviceId, -1);
}

/**
 * @tc.name: InputDeviceManagerTest_FindInputDeviceId_002
 * @tc.desc: Test FindInputDeviceId with non-existent device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FindInputDeviceId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    libinput_device* device = reinterpret_cast<libinput_device*>(0x12345678);
    
    auto deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    EXPECT_EQ(deviceId, -1);
}

/**
 * @tc.name: InputDeviceManagerTest_FindInputDeviceId_003
 * @tc.desc: Test FindInputDeviceId with existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_FindInputDeviceId_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    int32_t expectedId = 1;
    libinput_device* device = reinterpret_cast<libinput_device*>(0x12345678);
    
    InputDeviceManager::InputDeviceInfo info;
    info.inputDeviceOrigin = device;
    INPUT_DEV_MGR->inputDevice_[expectedId] = info;
    
    auto deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    EXPECT_EQ(deviceId, expectedId);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_GetPhysicalInputDevice_001
 * @tc.desc: Test GetPhysicalInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_GetPhysicalInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    std::string physicalId = "test_physical_id";
    auto physDev = INPUT_DEV_MGR->GetPhysicalInputDevice(physicalId);
    EXPECT_EQ(physDev, nullptr);
}

/**
 * @tc.name: InputDeviceManagerTest_UpdatePhysicalInputDevice_001
 * @tc.desc: Test UpdatePhysicalInputDevice with empty physicalId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_UpdatePhysicalInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.physicalId.clear();
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->UpdatePhysicalInputDevice(1, info));
}

/**
 * @tc.name: InputDeviceManagerTest_UpdatePhysicalInputDevice_002
 * @tc.desc: Test UpdatePhysicalInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_UpdatePhysicalInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.physicalId = "test_physical_id";
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->UpdatePhysicalInputDevice(1, info));
    
    auto physDev = INPUT_DEV_MGR->GetPhysicalInputDevice("test_physical_id");
    ASSERT_NE(physDev, nullptr);
    
    INPUT_DEV_MGR->physicalInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_RemoveInputDeviceFromPhysicalDevice_001
 * @tc.desc: Test RemoveInputDeviceFromPhysicalDevice with empty physicalId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RemoveInputDeviceFromPhysicalDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.physicalId.clear();
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->RemoveInputDeviceFromPhysicalDevice(1, ""));
}

/**
 * @tc.name: InputDeviceManagerTest_RemoveInputDeviceFromPhysicalDevice_002
 * @tc.desc: Test RemoveInputDeviceFromPhysicalDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RemoveInputDeviceFromPhysicalDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.physicalId = "test_physical_id";
    INPUT_DEV_MGR->UpdatePhysicalInputDevice(1, info);
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->RemoveInputDeviceFromPhysicalDevice(1, "test_physical_id"));
    
    auto physDev = INPUT_DEV_MGR->GetPhysicalInputDevice("test_physical_id");
    EXPECT_EQ(physDev, nullptr);
    
    INPUT_DEV_MGR->physicalInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_UpdateInputDeviceCaps_001
 * @tc.desc: Test UpdateInputDeviceCaps with non-existent device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_UpdateInputDeviceCaps_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->UpdateInputDeviceCaps(999));
}

/**
 * @tc.name: InputDeviceManagerTest_CheckInputDeviceCaps_001
 * @tc.desc: Test CheckInputDeviceCaps with non-existent device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_CheckInputDeviceCaps_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->CheckInputDeviceCaps(999));
}

/**
 * @tc.name: InputDeviceManagerTest_HasEnabledPhysicalPointerDevice_001
 * @tc.desc: Test HasEnabledPhysicalPointerDevice with no devices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasEnabledPhysicalPointerDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto result = INPUT_DEV_MGR->HasEnabledPhysicalPointerDevice();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_HasEnabledPhysicalPointerDevice_002
 * @tc.desc: Test HasEnabledPhysicalPointerDevice with pointer device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasEnabledPhysicalPointerDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.isPointerDevice = true;
    info.isRemote = false;
    info.isDeviceReportEvent = true;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    
    auto result = INPUT_DEV_MGR->HasEnabledPhysicalPointerDevice();
    EXPECT_TRUE(result);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_HasEnabledNoEventReportedPhysicalPointerDevice_001
 * @tc.desc: Test HasEnabledNoEventReportedPhysicalPointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasEnabledNoEventReportedPhysicalPointerDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto result = INPUT_DEV_MGR->HasEnabledNoEventReportedPhysicalPointerDevice();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_MakeVirtualDeviceInfo_001
 * @tc.desc: Test MakeVirtualDeviceInfo with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_MakeVirtualDeviceInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo deviceInfo;
    std::shared_ptr<InputDevice> device = nullptr;
    
    auto result = INPUT_DEV_MGR->MakeVirtualDeviceInfo(device, deviceInfo);
    EXPECT_EQ(result, ERROR_NULL_POINTER);
}

/**
 * @tc.name: InputDeviceManagerTest_MakeVirtualDeviceInfo_002
 * @tc.desc: Test MakeVirtualDeviceInfo with pointer device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_MakeVirtualDeviceInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo deviceInfo;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    
    auto result = INPUT_DEV_MGR->MakeVirtualDeviceInfo(device, deviceInfo);
    EXPECT_EQ(result, RET_OK);
    EXPECT_TRUE(deviceInfo.isPointerDevice);
    EXPECT_FALSE(deviceInfo.isTouchableDevice);
}

/**
 * @tc.name: InputDeviceManagerTest_MakeVirtualDeviceInfo_003
 * @tc.desc: Test MakeVirtualDeviceInfo with touch device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_MakeVirtualDeviceInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo deviceInfo;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    
    auto result = INPUT_DEV_MGR->MakeVirtualDeviceInfo(device, deviceInfo);
    EXPECT_EQ(result, RET_OK);
    EXPECT_TRUE(deviceInfo.isTouchableDevice);
    EXPECT_FALSE(deviceInfo.isPointerDevice);
}

/**
 * @tc.name: InputDeviceManagerTest_SetSpecialVirtualDevice_001
 * @tc.desc: Test SetSpecialVirtualDevice with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetSpecialVirtualDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->SetSpecialVirtualDevice(nullptr));
}

/**
 * @tc.name: InputDeviceManagerTest_SetSpecialVirtualDevice_002
 * @tc.desc: Test SetSpecialVirtualDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_SetSpecialVirtualDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto device = std::make_shared<InputDevice>();
    device->SetName("VirtualKeyboard");
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->SetSpecialVirtualDevice(device));
}

/**
 * @tc.name: InputDeviceManagerTest_AddVirtualInputDeviceInner_001
 * @tc.desc: Test AddVirtualInputDeviceInner with keyboard device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddVirtualInputDeviceInner_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    INPUT_DEV_MGR->virtualKeyboardEverConnected_ = false;
    
    int32_t deviceId = 1;
    auto device = std::make_shared<InputDevice>();
    device->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->AddVirtualInputDeviceInner(deviceId, device));
    EXPECT_EQ(INPUT_DEV_MGR->virtualKeyboardEverConnected_, true);
    
    INPUT_DEV_MGR->virtualInputDevices_.clear();
    INPUT_DEV_MGR->virtualKeyboardEverConnected_ = false;
}

/**
 * @tc.name: InputDeviceManagerTest_AddPhysicalInputDeviceInner_001
 * @tc.desc: Test AddPhysicalInputDeviceInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_AddPhysicalInputDeviceInner_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.physicalId = "test_physical_id";
    info.enable = true;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->AddPhysicalInputDeviceInner(1, info));
    
    auto physDev = INPUT_DEV_MGR->GetPhysicalInputDevice("test_physical_id");
    ASSERT_NE(physDev, nullptr);
    
    INPUT_DEV_MGR->inputDevice_.clear();
    INPUT_DEV_MGR->physicalInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_CheckDuplicateInputDevice_Libinput_002
 * @tc.desc: Test CheckDuplicateInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_CheckDuplicateInputDevice_Libinput_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    libinput_device* device = reinterpret_cast<libinput_device*>(0x12345678);
    
    InputDeviceManager::InputDeviceInfo info;
    info.inputDeviceOrigin = device;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    
    auto result = INPUT_DEV_MGR->CheckDuplicateInputDevice(device);
    EXPECT_TRUE(result);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_RemovePhysicalInputDeviceInner_001
 * @tc.desc: Test RemovePhysicalInputDeviceInner with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_RemovePhysicalInputDeviceInner_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    int32_t deviceId = -1;
    bool enable = false;
    bool isDeviceReportEvent = false;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->RemovePhysicalInputDeviceInner(nullptr, deviceId, enable, isDeviceReportEvent));
    EXPECT_EQ(deviceId, -1);
}

/**
 * @tc.name: InputDeviceManagerTest_HasLocalMouseDevice_001
 * @tc.desc: Test HasLocalMouseDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasLocalMouseDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto result = INPUT_DEV_MGR->HasLocalMouseDevice();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_HasTouchDevice_001
 * @tc.desc: Test HasTouchDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasTouchDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto result = INPUT_DEV_MGR->HasTouchDevice();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputDeviceManagerTest_HasTouchDevice_002
 * @tc.desc: Test HasTouchDevice with touch device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasTouchDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.isTouchableDevice = true;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    
    auto result = INPUT_DEV_MGR->HasTouchDevice();
    EXPECT_TRUE(result);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_HasPointerDevice_002
 * @tc.desc: Test HasPointerDevice with pointer device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasPointerDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.isPointerDevice = true;
    info.isRemote = false;
    info.isDeviceReportEvent = true;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    
    auto result = INPUT_DEV_MGR->HasPointerDevice();
    EXPECT_TRUE(result);
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_HasPointerDevice_003
 * @tc.desc: Test HasPointerDevice with remote pointer device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_HasPointerDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.isPointerDevice = true;
    info.isRemote = true;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    
    auto result = INPUT_DEV_MGR->HasPointerDevice();
    EXPECT_TRUE(result);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_CheckDevice_002
 * @tc.desc: Test CheckDevice with physical device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_CheckDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    
    InputDeviceManager::InputDeviceInfo info;
    info.enable = true;
    INPUT_DEV_MGR->inputDevice_[deviceId] = info;
    
    auto result = INPUT_DEV_MGR->CheckDevice(deviceId, 
        [](const IInputDeviceManager::IInputDevice& dev) { return true; });
    EXPECT_TRUE(result);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_CheckDevice_003
 * @tc.desc: Test CheckDevice with virtual device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_CheckDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1000;
    
    auto device = std::make_shared<InputDevice>();
    device->SetId(deviceId);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;
    
    auto result = INPUT_DEV_MGR->CheckDevice(deviceId, 
        [](const IInputDeviceManager::IInputDevice& dev) { return true; });
    EXPECT_TRUE(result);
    
    INPUT_DEV_MGR->virtualInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_ForEachDevice_002
 * @tc.desc: Test ForEachDevice with devices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ForEachDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    info.enable = true;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    INPUT_DEV_MGR->inputDevice_[2] = info;
    
    auto device = std::make_shared<InputDevice>();
    device->SetId(1000);
    INPUT_DEV_MGR->virtualInputDevices_[1000] = device;
    
    int count = 0;
    INPUT_DEV_MGR->ForEachDevice([&count](int32_t id, const IInputDeviceManager::IInputDevice& dev) {
        count++;
    });
    
    EXPECT_EQ(count, 3);
    
    INPUT_DEV_MGR->inputDevice_.clear();
    INPUT_DEV_MGR->virtualInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_ForDevice_002
 * @tc.desc: Test ForDevice with physical device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ForDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    
    InputDeviceManager::InputDeviceInfo info;
    info.enable = true;
    INPUT_DEV_MGR->inputDevice_[deviceId] = info;
    
    bool called = false;
    INPUT_DEV_MGR->ForDevice(deviceId, [&called](const IInputDeviceManager::IInputDevice& dev) {
        called = true;
    });
    
    EXPECT_TRUE(called);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_ForDevice_003
 * @tc.desc: Test ForDevice with virtual device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ForDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1000;
    
    auto device = std::make_shared<InputDevice>();
    device->SetId(deviceId);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;
    
    bool called = false;
    INPUT_DEV_MGR->ForDevice(deviceId, [&called](const IInputDeviceManager::IInputDevice& dev) {
        called = true;
    });
    
    EXPECT_TRUE(called);
    
    INPUT_DEV_MGR->virtualInputDevices_.clear();
}

/**
 * @tc.name: InputDeviceManagerTest_ForOneDevice_001
 * @tc.desc: Test ForOneDevice with null predicates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ForOneDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->ForOneDevice(nullptr, nullptr));
    ASSERT_NO_FATAL_FAILURE(INPUT_DEV_MGR->ForOneDevice(
        [](int32_t id, const IInputDeviceManager::IInputDevice& dev) { return true; }, nullptr));
}

/**
 * @tc.name: InputDeviceManagerTest_ForOneDevice_002
 * @tc.desc: Test ForOneDevice with matching device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, InputDeviceManagerTest_ForOneDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    InputDeviceManager::InputDeviceInfo info;
    INPUT_DEV_MGR->inputDevice_[1] = info;
    INPUT_DEV_MGR->inputDevice_[2] = info;
    
    int foundId = -1;
    INPUT_DEV_MGR->ForOneDevice(
        [&foundId](int32_t id, const IInputDeviceManager::IInputDevice& dev) { return id == 1; },
        [&foundId](int32_t id, const IInputDeviceManager::IInputDevice& dev) { foundId = id; });
    
    EXPECT_EQ(foundId, 1);
    
    INPUT_DEV_MGR->inputDevice_.clear();
}
} // namespace MMI
} // namespace OHOS
