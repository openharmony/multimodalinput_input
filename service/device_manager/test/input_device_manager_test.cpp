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
 * @tc.name: ParseDeviceId_Test_001
 * @tc.desc: Test the function ParseDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, ParseDeviceId_Test_001, TestSize.Level1)
{
    InputDeviceManager inputDevice;
    std::string sysName = "test";
    int32_t ret = inputDevice.ParseDeviceId(sysName);
    EXPECT_EQ(ret, RET_ERR);
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
 * @tc.name: GetKeyboardDevice_Test_001
 * @tc.desc: Test the function GetKeyboardDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTest, GetKeyboardDevice_Test_001, TestSize.Level1)
{
    InputDeviceManager inputDevice;
    struct libinput_device *inputDev = inputDevice.GetKeyboardDevice();
    inputDev = inputDevice.GetKeyboardDevice();
    EXPECT_EQ(inputDev, nullptr);
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
} // namespace MMI
} // namespace OHOS
