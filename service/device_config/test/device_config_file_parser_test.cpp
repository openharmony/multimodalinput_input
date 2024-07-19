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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "device_config_file_parser.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DeviceConfigFileParserTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MockLibinputDevice {
public:
    virtual uint32_t libinput_device_get_id_vendor() const { return 123; }
    virtual uint32_t libinput_device_get_id_product() const { return 456; }
    virtual uint32_t libinput_device_get_id_version() const { return 789; }
    virtual const char* LibinputDeviceGetName() const { return "MockDevice"; }
};

/**
 * @tc.name: DeviceConfigFileParserTest_CombDeviceFileName_001
 * @tc.desc: Test the function CombDeviceFileName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceConfigFileParserTest, DeviceConfigFileParserTest_CombDeviceFileName_001, TestSize.Level1)
{
    class MockLibinputDeviceNullName : public MockLibinputDevice {
    public:
        const char* LibinputDeviceGetName() const override { return nullptr; }
    };

    MockLibinputDeviceNullName mockDevice;
    DeviceConfigManagement configManager;
    std::string fileName = configManager.CombDeviceFileName(reinterpret_cast<struct libinput_device*>(&mockDevice));
    EXPECT_NE(fileName, "63373_13888_63373_x");
}

/**
 * @tc.name: DeviceConfigFileParserTest_ConfigItemName2Id_001
 * @tc.desc: Test the function ConfigItemName2Id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceConfigFileParserTest, DeviceConfigFileParserTest_ConfigItemName2Id_001, TestSize.Level1)
{
    DeviceConfigManagement configManager;
    ConfigFileItem ret = configManager.ConfigItemName2Id("speed");
    EXPECT_EQ(ret, ConfigFileItem::POINTER_SPEED);
    ret = configManager.ConfigItemName2Id("invalid_name");
    EXPECT_EQ(ret, ConfigFileItem::INVALID);
}

/**
 * @tc.name: DeviceConfigFileParserTest_ReadConfigFile_001
 * @tc.desc: Test the function ReadConfigFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceConfigFileParserTest, DeviceConfigFileParserTest_ReadConfigFile_001, TestSize.Level1)
{
    DeviceConfigManagement configManager;
    std::map<ConfigFileItem, int32_t> configList = configManager.ReadConfigFile("empty.txt");
    EXPECT_TRUE(configList.empty());
    configList = configManager.ReadConfigFile("comment.cfg");
    EXPECT_TRUE(configList.empty());
    configList = configManager.ReadConfigFile("no_valid_line.txt");
    EXPECT_TRUE(configList.empty());
    configList = configManager.ReadConfigFile("valid.cfg");
    EXPECT_TRUE(configList.empty());
}

/**
 * @tc.name: DeviceConfigFileParserTest_GetVendorConfig_002
 * @tc.desc: Test the function GetVendorConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceConfigFileParserTest, DeviceConfigFileParserTest_GetVendorConfig_002, TestSize.Level1)
{
    DeviceConfigManagement configManager;
    struct libinput_device *device = nullptr;
    VendorConfig vendorconfig = configManager.GetVendorConfig(device);
    EXPECT_EQ(vendorconfig.pointerSpeed, -1);
}
} // namespace MMI
} // namespace OHOS