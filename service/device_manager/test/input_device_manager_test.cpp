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

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
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
    InputDeviceManager manager;
    InputDeviceManager::InputDeviceInfo info1;
    info1.networkIdOrigin = "device1";
    info1.enable = true;
    manager.inputDevice_[1] = info1;
    InputDeviceManager::InputDeviceInfo info2;
    info2.networkIdOrigin = "device2";
    info2.enable = false;
    manager.inputDevice_[2] = info2;
    InputDeviceManager::InputDeviceInfo info3;
    info3.networkIdOrigin = "device3";
    info3.enable = true;
    manager.inputDevice_[3] = info3;
    auto ids = manager.GetInputDeviceIds();
    ASSERT_EQ(ids.size(), 2);
    EXPECT_EQ(ids[0], 1);
    EXPECT_EQ(ids[1], 3);
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
    InputDeviceManager manager;
    InputDeviceManager::InputDeviceInfo info;
    info.networkIdOrigin = "device1";
    info.enable = true;
    manager.inputDevice_[1] = info;
    std::vector<int32_t> keyCodes = {1};
    std::vector<bool> keystroke;
    int32_t ret = manager.SupportKeys(1, keyCodes, keystroke);
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
    InputDeviceManager manager;
    int32_t keyboardType;
    int32_t ret = manager.GetDeviceConfig(-1, keyboardType);
    ASSERT_EQ(ret, false);
    InputDeviceManager::InputDeviceInfo info;
    info.networkIdOrigin = "device1";
    manager.inputDevice_[1] = info;
    ret = manager.GetDeviceConfig(1, keyboardType);
    ASSERT_EQ(ret, false);
    std::map<int32_t, DeviceConfig> deviceConfig;
    DeviceConfig config;
    config.keyboardType = 1;
    deviceConfig[1] = config;
    ret = manager.GetDeviceConfig(1, keyboardType);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 1;
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.sysUid = "";
    deviceManager.NotifyDevRemoveCallback(deviceId, deviceInfo);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 0;
    int32_t MAX_VIRTUAL_INPUT_DEVICE_NUM = 128;
    for (int i = 0; i < MAX_VIRTUAL_INPUT_DEVICE_NUM; i++) {
        deviceManager.virtualInputDevices_.insert(std::make_pair(i, std::make_shared<InputDevice>()));
    }
    EXPECT_EQ(deviceManager.GenerateVirtualDeviceId(deviceId), RET_ERR);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 0;
    deviceManager.virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(deviceManager.GenerateVirtualDeviceId(deviceId), RET_OK);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 0;
    EXPECT_EQ(deviceManager.GenerateVirtualDeviceId(deviceId), RET_OK);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 1;
    EXPECT_EQ(deviceManager.RemoveVirtualInputDevice(deviceId), RET_ERR);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 1;
    deviceManager.virtualInputDevices_[deviceId] = std::make_shared<InputDevice>();
    EXPECT_EQ(deviceManager.RemoveVirtualInputDevice(deviceId), RET_OK);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 1;
    auto device = std::make_shared<InputDevice>();
    deviceManager.virtualInputDevices_[deviceId] = device;
    EXPECT_EQ(deviceManager.RemoveVirtualInputDevice(deviceId), RET_OK);
    EXPECT_EQ(deviceManager.virtualInputDevices_.find(deviceId), deviceManager.virtualInputDevices_.end());
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
    InputDeviceManager manager;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    int32_t deviceId = 0;
    std::shared_ptr<InputDevice> device;
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = manager.AddVirtualInputDevice(device, deviceId);
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
    InputDeviceManager manager;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    int32_t deviceId = 1;
    std::shared_ptr<InputDevice> device;
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = manager.AddVirtualInputDevice(device, deviceId);
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
    InputDeviceManager manager;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    int32_t deviceId = 1;
    std::shared_ptr<InputDevice> device;
    EXPECT_CALL(*mockDevice, MakeVirtualDeviceInfo()).WillRepeatedly(testing::Return(RET_OK));
    int32_t ret = manager.AddVirtualInputDevice(device, deviceId);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 1;
    std::shared_ptr<InputDevice> device;

    int32_t MAX_VIRTUAL_INPUT_DEVICE_NUM = 128;
    for (int i = 0; i < MAX_VIRTUAL_INPUT_DEVICE_NUM; i++) {
        deviceManager.virtualInputDevices_.insert(std::make_pair(i, std::make_shared<InputDevice>()));
    }

    EXPECT_EQ(deviceManager.GenerateVirtualDeviceId(deviceId), RET_ERR);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 2;
    std::shared_ptr<InputDevice> device;
    deviceManager.virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(deviceManager.GenerateVirtualDeviceId(deviceId), RET_OK);

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
    InputDeviceManager deviceManager;
    int32_t deviceId = 2;
    std::shared_ptr<InputDevice> device;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    deviceManager.virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(deviceManager.GenerateVirtualDeviceId(deviceId), RET_OK);
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
    InputDeviceManager deviceManager;
    int32_t deviceId = 2;
    std::shared_ptr<InputDevice> device;
    std::shared_ptr<MockInputDevice> mockDevice = std::make_shared<MockInputDevice>();
    deviceManager.virtualInputDevices_.insert(std::make_pair(1, std::make_shared<InputDevice>()));
    EXPECT_EQ(deviceManager.GenerateVirtualDeviceId(deviceId), RET_OK);
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
    InputDeviceManager inputDeviceManager;
    int32_t deviceId = 1;
    int32_t keyboardType = 0;
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    inputDeviceManager.virtualInputDevices_.insert(std::make_pair(deviceId, device));
    EXPECT_EQ(inputDeviceManager.GetKeyboardType(deviceId, keyboardType), RET_OK);
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
    InputDeviceManager inputDeviceManager;
    int32_t deviceId = 2;
    int32_t keyboardType = 0;
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    inputDeviceManager.virtualInputDevices_.insert(std::make_pair(deviceId, device));
    EXPECT_EQ(inputDeviceManager.GetKeyboardType(deviceId, keyboardType), RET_OK);
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
    InputDeviceManager inputDeviceManager;
    int32_t deviceId = 3;
    int32_t keyboardType = 0;
    inputDeviceManager.inputDevice_.insert(std::make_pair(deviceId, InputDeviceManager::InputDeviceInfo()));
    inputDeviceManager.inputDevice_[deviceId].enable = false;
    EXPECT_EQ(inputDeviceManager.GetKeyboardType(deviceId, keyboardType), RET_ERR);
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
    InputDeviceManager inputDevice;
    bool enable = true;
    int32_t keyboardType = KEYBOARD_TYPE_NONE;
    EXPECT_TRUE(keyboardType != KEYBOARD_TYPE_ALPHABETICKEYBOARD);
    int32_t ret = inputDevice.OnEnableInputDevice(enable);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = true;
    deviceInfo.enable = false;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));

    int32_t ret = inputDevice.OnEnableInputDevice(enable);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = true;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));

    int32_t ret = inputDevice.OnEnableInputDevice(enable);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 5;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = false;
    deviceInfo.isPointerDevice = false;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    
    int32_t ret = inputDevice.OnEnableInputDevice(enable);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = false;
    deviceInfo.isPointerDevice = true;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    
    int32_t ret = inputDevice.OnEnableInputDevice(enable);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 3;
    bool enable = true;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.enable = true;
    deviceInfo.isPointerDevice = true;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    
    int32_t ret = inputDevice.OnEnableInputDevice(enable);
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
    InputDeviceManager inputDevice;
    struct libinput_device *device = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);

    bool ret1 = inputDevice.IsMatchKeys(device, keyCodes);
    EXPECT_FALSE(ret1);
    auto ret2 = inputDevice.GetKeyboardDevice();
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
    InputDeviceManager inputDevice;
    int32_t deviceId;
    struct libinput_device *device = nullptr;
    deviceId = 2;
    ASSERT_NO_FATAL_FAILURE(inputDevice.OnInputDeviceAdded(device));
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
    int32_t returnCode1 = 401;
    int32_t returnCode2 = 65142786;
    InputDeviceManager inputDevice;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_HOME);
    keyCodes.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    keyCodes.push_back(KeyEvent::KEYCODE_F2);

    int32_t ret1 = inputDevice.GetKeyboardBusMode(deviceId);
    EXPECT_EQ(ret1, returnCode2);
    int32_t ret2 = inputDevice.GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret2, returnCode1);
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
    InputDeviceManager inputDevice;
    std::shared_ptr<InputDevice> inputDeviceManager{nullptr};
    int32_t id = 1;
    bool checked = true;
    inputDeviceManager = inputDevice.GetInputDevice(id, checked);
    EXPECT_EQ(inputDeviceManager, nullptr);
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
    InputDeviceManager inputDevice;
    ASSERT_NO_FATAL_FAILURE(inputDevice.GetInputDeviceIds());
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    std::vector<int32_t> keyCodes{12};
    std::vector<bool> keystroke{true};
    int32_t returnCode = 401;
    int32_t ret = inputDevice.SupportKeys(deviceId, keyCodes, keystroke);
    EXPECT_EQ(ret, returnCode);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    bool ret = inputDevice.GetDeviceConfig(deviceId, keyboardType);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t returnCode = 401;
    int32_t ret = inputDevice.GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t returnCode = 401;
    int32_t ret = inputDevice.GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
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
    InputDeviceManager inputDevice;
    bool ret = inputDevice.HasTouchDevice();
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
    InputDeviceManager inputDevice;
    ASSERT_NO_FATAL_FAILURE(inputDevice.ScanPointerDevice());
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
    InputDeviceManager inputDevice;
    int32_t fd = 1;
    std::vector<std::string> args{"test"};
    ASSERT_NO_FATAL_FAILURE(inputDevice.Dump(fd, args));
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
    InputDeviceManager inputDevice;
    int32_t fd = 1;
    std::vector<std::string> args{"test"};
    ASSERT_NO_FATAL_FAILURE(inputDevice.DumpDeviceList(fd, args));
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    ASSERT_NO_FATAL_FAILURE(inputDevice.GetVendorConfig(deviceId));
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
    InputDeviceManager inputDevice;
    bool enable = true;
    int32_t ret = inputDevice.OnEnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);
    enable = false;
    ret = inputDevice.OnEnableInputDevice(enable);
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
    InputDeviceManager inputDevice;
    ASSERT_NO_FATAL_FAILURE(inputDevice.InitSessionLostCallback());
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
    InputDeviceManager inputDevice;
    inputDevice.sessionLostCallbackInitialized_ = true;
    ASSERT_NO_FATAL_FAILURE(inputDevice.InitSessionLostCallback());
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
    InputDeviceManager inputDevice;
    inputDevice.sessionLostCallbackInitialized_ = false;
    ASSERT_NO_FATAL_FAILURE(inputDevice.InitSessionLostCallback());
    EXPECT_FALSE(inputDevice.sessionLostCallbackInitialized_);
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
    InputDeviceManager inputDevice;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> session = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    ASSERT_NE(session, nullptr);
    ASSERT_NO_FATAL_FAILURE(inputDevice.OnSessionLost(session));
    session = nullptr;
    ASSERT_NO_FATAL_FAILURE(inputDevice.OnSessionLost(session));
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
    InputDeviceManager inputDevice;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(true));
    int32_t result = inputDevice.NotifyMessage(mockSession, 1, "type");
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
    InputDeviceManager inputDevice;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(false));
    int32_t result = inputDevice.NotifyMessage(mockSession, 1, "type");
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
    InputDeviceManager inputDevice;
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> mockSession = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    EXPECT_CALL(*mockSession, SendMsg(testing::_)).WillRepeatedly(testing::Return(false));
    SessionPtr nullSession = nullptr;
    int32_t result = inputDevice.NotifyMessage(nullSession, 1, "type");
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
    InputDeviceManager inputDevice;

    int32_t id = -1;
    bool checked = true;
    std::shared_ptr inputDeviceManager = inputDevice.GetInputDevice(id, checked);
    EXPECT_EQ(inputDeviceManager, nullptr);
    id = 1;
    checked = false;
    inputDeviceManager = inputDevice.GetInputDevice(id, checked);
    EXPECT_EQ(inputDeviceManager, nullptr);
    id = -1;
    checked = false;
    inputDeviceManager = inputDevice.GetInputDevice(id, checked);
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
    InputDeviceManager manager;
    std::vector<int32_t> expectedIds = {1, 2, 3};
    std::vector<int32_t> actualIds = manager.GetInputDeviceIds();
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    int32_t COMMON_PARAMETER_ERROR = 401;
    std::vector<int32_t> keyCodes = {1, 2, 3};
    std::vector<bool> keystrokes{true};
    int32_t ret = inputDevice.SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_NE(keystrokes.size(), keyCodes.size());
    EXPECT_TRUE(keystrokes[0]);
    EXPECT_FALSE(keystrokes[1]);
    EXPECT_FALSE(keystrokes[2]);
    deviceId = -1;
    keyCodes = {1, 2, 3};
    ret = inputDevice.SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_FALSE(keystrokes.empty());
    deviceId = 100;
    keyCodes = {1, 2, 3};
    ret = inputDevice.SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_FALSE(keystrokes.empty());
    deviceId = 1;
    keyCodes.clear();
    keystrokes.clear();
    ret = inputDevice.SupportKeys(deviceId, keyCodes, keystrokes);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = -1;
    int32_t keyboardType = 5;
    bool ret = inputDevice.GetDeviceConfig(deviceId, keyboardType);
    EXPECT_FALSE(ret);
    deviceId = 10;
    keyboardType = -3;
    ret = inputDevice.GetDeviceConfig(deviceId, keyboardType);
    EXPECT_FALSE(ret);
    deviceId = -8;
    keyboardType = -10;
    ret = inputDevice.GetDeviceConfig(deviceId, keyboardType);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    int32_t ret = inputDevice.GetKeyboardBusMode(deviceId);
    EXPECT_NE(ret, 0);
    deviceId = 0;
    ret = inputDevice.GetKeyboardBusMode(deviceId);
    EXPECT_NE(ret, 0);
    deviceId = -5;
    ret = inputDevice.GetKeyboardBusMode(deviceId);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    int32_t keyboardType = -5;
    int32_t returnCode = 401;
    int32_t ret = inputDevice.GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
    deviceId = -1;
    keyboardType = 2;
    ret = inputDevice.GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
    deviceId = -1;
    keyboardType = -2;
    ret = inputDevice.GetDeviceSupportKey(deviceId, keyboardType);
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
    InputDeviceManager inputDevice;
    int32_t deviceId = 1;
    int32_t keyboardType = -100;
    int32_t returnCode = 401;
    int32_t ret = inputDevice.GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
    deviceId = -1;
    keyboardType = 1;
    ret = inputDevice.GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
    deviceId = -10;
    keyboardType = -5;
    ret = inputDevice.GetKeyboardType(deviceId, keyboardType);
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
    InputDeviceManager inputDevice;
    using InputDeviceCallback = std::function<void(int, std::string, std::string)>;
    InputDeviceCallback callback = [](int status, const std::string& deviceName, const std::string& deviceId) {
    };
    ASSERT_NO_FATAL_FAILURE(inputDevice.SetInputStatusChangeCallback(callback));
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
    InputDeviceManager inputDevice;
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    ASSERT_NO_FATAL_FAILURE(inputDevice.AddDevListener(session));
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
    InputDeviceManager inputDevice;
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    ASSERT_NO_FATAL_FAILURE(inputDevice.RemoveDevListener(session));
}

/**
 * @tc.name: HasPointerDevice_Test_001
 * @tc.desc: Test the function HasPointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, HasPointerDevice_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager inputDevice;
    bool ret = inputDevice.HasPointerDevice();
    EXPECT_FALSE(ret);
    ret = inputDevice.HasTouchDevice();
    EXPECT_FALSE(ret);
}

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
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevCallback(deviceId, inDevice));
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
    InputDeviceManager inputDevice;
    libinput_device* inputDevices = nullptr;
    ASSERT_NO_FATAL_FAILURE(inputDevice.OnInputDeviceAdded(inputDevices));
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
    InputDeviceManager inputDevice;
    libinput_device* inputDevices = nullptr;
    ASSERT_NO_FATAL_FAILURE(inputDevice.OnInputDeviceRemoved(inputDevices));
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
    InputDeviceManager inputDevice;
    int32_t id = 30;
    ASSERT_FALSE(inputDevice.IsRemote(id));
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
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inputDeviceInfo;
    int32_t id = 30;
    inputDeviceInfo.isRemote = true;
    inputDevice.inputDevice_.insert(std::make_pair(id, inputDeviceInfo));
    ASSERT_TRUE(inputDevice.IsRemote(id));
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
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceid = -1;
    inDevice.isTouchableDevice = false;
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevCallback(deviceid, inDevice));
    inDevice.isTouchableDevice = true;
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevCallback(deviceid, inDevice));
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
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceid = 1;
    inDevice.isTouchableDevice = true;
    inDevice.sysUid = "123456";
    using inputDeviceCallback = std::function<void(int32_t deviceId, std::string devName, std::string devStatus)>;
    inputDeviceCallback callback = [](int32_t deviceId, std::string devName, std::string devStatus) {};
    inputDevice.SetInputStatusChangeCallback(callback);
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevCallback(deviceid, inDevice));
    inDevice.sysUid.clear();
    ASSERT_NO_FATAL_FAILURE(inputDevice.NotifyDevCallback(deviceid, inDevice));
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
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 10;
    inDevice.isPointerDevice = false;
    inDevice.enable = false;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, inDevice));
    deviceId = 15;
    inDevice.isPointerDevice = true;
    inDevice.enable = true;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, inDevice));
    ASSERT_NO_FATAL_FAILURE(inputDevice.ScanPointerDevice());
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
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 10;
    inDevice.isPointerDevice = false;
    inDevice.enable = false;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, inDevice));
    ASSERT_NO_FATAL_FAILURE(inputDevice.ScanPointerDevice());
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
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 5;
    inDevice.isPointerDevice = false;
    inDevice.enable = false;
    inDevice.dhid = 2;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, inDevice));
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
    InputDeviceManager inputDevice;
    InputDeviceManager::InputDeviceInfo inDevice;
    int32_t deviceId = 3;
    inDevice.enable = false;
    inDevice.dhid = 2;
    inputDevice.inputDevice_.insert(std::make_pair(deviceId, inDevice));
    inputDevice.inputDevice_.clear();
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
    InputDeviceManager deviceMgr;
    int32_t deviceId = 3;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.inputDeviceOrigin = nullptr;
    deviceMgr.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    EXPECT_TRUE(deviceInfo.inputDeviceOrigin == inputDevice);
    ASSERT_NO_FATAL_FAILURE(deviceMgr.OnInputDeviceAdded(inputDevice));
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
    InputDeviceManager deviceMgr;
    int32_t deviceId = 3;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.isPointerDevice = true;
    deviceInfo.enable = true;
    deviceMgr.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    ASSERT_NO_FATAL_FAILURE(deviceMgr.OnInputDeviceAdded(inputDevice));
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
    InputDeviceManager deviceMgr;
    int32_t deviceId = 5;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.inputDeviceOrigin = nullptr;
    deviceMgr.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    EXPECT_TRUE(deviceInfo.inputDeviceOrigin == inputDevice);
    ASSERT_NO_FATAL_FAILURE(deviceMgr.OnInputDeviceRemoved(inputDevice));
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
    InputDeviceManager deviceMgr;
    int32_t deviceId = 5;
    struct libinput_device *inputDevice = nullptr;

    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = false;
    deviceInfo.isPointerDevice = true;
    deviceMgr.inputDevice_.insert(std::make_pair(deviceId, deviceInfo));

    std::string sysUid;
    EXPECT_TRUE(sysUid.empty());
    ASSERT_NO_FATAL_FAILURE(deviceMgr.OnInputDeviceRemoved(inputDevice));
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
    InputDeviceManager deviceMgr;
    struct libinput_device *device = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);

    bool ret1 = INPUT_DEV_MGR->IsMatchKeys(device, keyCodes);
    EXPECT_FALSE(ret1);
    auto ret2 = deviceMgr.GetKeyboardDevice();
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
    InputDeviceManager deviceMgr;
    struct libinput_device *device = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    INPUT_DEV_MGR->inputDevice_.clear();
    bool ret1 = INPUT_DEV_MGR->IsMatchKeys(device, keyCodes);
    EXPECT_FALSE(ret1);
    auto ret2 = deviceMgr.GetKeyboardDevice();
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

    InputDeviceManager inputDevice;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_HOME);
    keyCodes.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    keyCodes.push_back(KeyEvent::KEYCODE_F2);

    int32_t ret = INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, supportKey);
    EXPECT_NE(ret, RET_OK);
    int32_t ret2 = inputDevice.GetDeviceSupportKey(deviceId, keyboardType);
    EXPECT_EQ(ret2, returnCode1);
}
} // namespace MMI
} // namespace OHOS
