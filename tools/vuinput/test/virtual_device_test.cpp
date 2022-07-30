/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include "virtual_device.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class VirtualDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    const std::string DEVICE = "Virtual Mouse";
    const uint16_t BUS_TYPE = BUS_USB;
    const uint16_t VENDOR_ID = 0x93a;
    const uint16_t PRODUCT_ID = 0x2510;
};

/**
 * @tc.name:Test_CreateHandle_mouse
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_mouse, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "mouse";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_keyboard
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_keyboard, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "keyboard";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_knob
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_knob, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "knob";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_joystick
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_joystick, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "joystick";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_trackball
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_trackball, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "trackball";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_remotecontrol
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_remotecontrol, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "remotecontrol";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_trackpad
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_trackpad, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "trackpad";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_gamepad
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_gamepad, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "gamepad";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_touchpad
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_touchpad, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "touchpad";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_touchscreen
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_touchscreen, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "touchscreen";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_CreateHandle_phone
 * @tc.desc:Verify VirtualDevice function CreateHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CreateHandle_phone, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceType = "phone";
    auto ret = device.CreateHandle(deviceType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_AddDevice_false01
 * @tc.desc:Verify VirtualDevice function AddDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_AddDevice_false01, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceName = "";
    auto ret = device.AddDevice(deviceName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_AddDevice_true
 * @tc.desc:Verify VirtualDevice function AddDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_AddDevice_true, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceName = "mouse";
    auto ret = device.AddDevice(deviceName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_AddDevice_false02
 * @tc.desc:Verify VirtualDevice function AddDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_AddDevice_false02, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string deviceName = "falseName";
    auto ret = device.AddDevice(deviceName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_CloseDevice_flase02
 * @tc.desc:Verify VirtualDevice function CloseDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_CloseDevice_flase02, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> fileList;
    std::string fileName = "falseArgv";
    fileList.push_back("close ");
    fileList.push_back("falseArgv ");
    auto ret = device.CloseDevice(fileName, fileList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_FindDevice_listfalse01
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_listfalse01, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("list");
    auto ret = device.CommandBranch(argvList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_FindDevice_listfalse02
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_listfalse02, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("list ");
    argvList.push_back("falseArgv");
    auto ret = device.CommandBranch(argvList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_FindDevice_addFalse
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_addFalse, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("start ");
    argvList.push_back("falseArgv");
    auto ret = device.CommandBranch(argvList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_FindDevice_addTrue
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_addTrue, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("start");
    argvList.push_back("mouse");
    auto ret = device.CommandBranch(argvList);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name:Test_FindDevice_closeFalse01
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_closeFalse01, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("close ");
    argvList.push_back("falsePid");
    auto ret = device.CommandBranch(argvList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_FindDevice_closeTrue01
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_closeTrue01, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::string symbolFileTest;
    symbolFileTest.append(g_folderPath).append("1111111").append("_").append("testDevice");
    std::ofstream flagFile;
    flagFile.open(symbolFileTest.c_str());
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("close ");
    argvList.push_back("1111111");
    auto ret = device.CommandBranch(argvList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_FindDevice_mkdirFalse01
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_mkdirFalse01, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("close ");
    argvList.push_back("falsePid");
    auto ret = device.CommandBranch(argvList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_FindDevice_False01
 * @tc.desc:Verify VirtualDevice function CommandBranch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_FindDevice_False01, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    std::vector<std::string> argvList;
    argvList.push_back("binName ");
    argvList.push_back("falseArgv ");
    auto ret = device.CommandBranch(argvList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_DoIoctl_false
 * @tc.desc:Verify VirtualDevice function DoIoctl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_DoIoctl_false, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    auto ret = device.DoIoctl(-1, UI_SET_KEYBIT, KEY_POWER);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name:Test_SetUp_01
 * @tc.desc:Verify VirtualDevice function SetUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualDeviceTest, Test_SetUp_01, TestSize.Level1)
{
    VirtualDevice device(DEVICE, BUS_TYPE, VENDOR_ID, PRODUCT_ID);
    auto ret = device.SetUp();
    EXPECT_TRUE(ret);
}
} // namespace MMI
} // namespace OHOS