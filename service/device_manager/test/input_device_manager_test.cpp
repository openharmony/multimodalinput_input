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

#include <fstream>

#include <gtest/gtest.h>
#include "libinput-private.h"

#include "mmi_log.h"
#include "uds_server.h"

#include "input_device_manager.h"

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

/**
 * @tc.name: GetInputDevice_Test_001
 * @tc.desc: Test the function GetInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetInputDevice_Test_001, TestSize.Level1)
{
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
    InputDeviceManager inputDevice;
    ASSERT_NO_FATAL_FAILURE(inputDevice.InitSessionLostCallback());
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
    std::shared_ptr<InputDevice> inputDeviceManager{nullptr};
    int32_t id = -1;
    bool checked = true;
    inputDeviceManager = inputDevice.GetInputDevice(id, checked);
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
    struct InputDeviceInfo {
        bool enable;
    };
    std::map<int32_t, struct InputDeviceInfo> inputDevice_;
    InputDeviceManager manager;
    inputDevice_[1] = {true};
    inputDevice_[2] = {true};
    inputDevice_[3] = {true};
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
    int32_t COMMON_PARAMETER_ERROR =401;
    std::vector<int32_t> keyCodes = {1, 2, 3};
    std::vector<bool> keystroke{true};
    int32_t ret = inputDevice.SupportKeys(deviceId, keyCodes, keystroke);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_NE(keystroke.size(), keyCodes.size());
    EXPECT_TRUE(keystroke[0]);
    EXPECT_FALSE(keystroke[1]);
    EXPECT_FALSE(keystroke[2]);
    deviceId = -1;
    keyCodes = {1, 2, 3};
    ret = inputDevice.SupportKeys(deviceId, keyCodes, keystroke);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_FALSE(keystroke.empty());
    deviceId = 100;
    keyCodes = {1, 2, 3};
    ret = inputDevice.SupportKeys(deviceId, keyCodes, keystroke);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_FALSE(keystroke.empty());
    deviceId = 1;
    std::vector<int32_t> keyCode;
    std::vector<bool> keystrokes;
    ret = inputDevice.SupportKeys(deviceId, keyCode, keystrokes);
    EXPECT_EQ(ret, COMMON_PARAMETER_ERROR);
    EXPECT_FALSE(keystroke.empty());
}

/**
 * @tc.name: IsMatchKeys_Test_001
 * @tc.desc: Test the function IsMatchKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, IsMatchKeys_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceManager inputDevice;
    libinput_device* deviceOrigin = new(std::nothrow)libinput_device;
    std::vector<int32_t> keyCodes = {1, 2, 3};
    ASSERT_NO_FATAL_FAILURE(inputDevice.IsMatchKeys(deviceOrigin, keyCodes));
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
} // namespace MMI
} // namespace OHOS
