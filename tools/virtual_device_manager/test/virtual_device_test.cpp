/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class VirtualDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

static const String DEVICE = "Virtual Mouse";
static const uint16_t BUSTYPE = BUS_USB;
static const uint16_t VENDOID = 0x93a;
static const uint16_t PRODUCTID = 0x2510;
static VirtualDevice VIRTUALDEVICETEST(DEVICE, BUSTYPE, VENDOID, PRODUCTID);

HWTEST_F(VirtualDeviceTest, Test_MakeFolder_01, TestSize.Level1)
{
    String folderPath = "/data/symbol/";
    VIRTUALDEVICETEST.MakeFolder(folderPath);
}

HWTEST_F(VirtualDeviceTest, Test_MakeFolder_02, TestSize.Level1)
{
    String folderPath = "/data/symbol1";
    VIRTUALDEVICETEST.MakeFolder(folderPath);
    remove(folderPath.c_str());
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_mouse, TestSize.Level1)
{
    String deviceType = "mouse";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_keyboard, TestSize.Level1)
{
    String deviceType = "keyboard";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_knob, TestSize.Level1)
{
    String deviceType = "knob";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_joystick, TestSize.Level1)
{
    String deviceType = "joystick";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_trackball, TestSize.Level1)
{
    String deviceType = "trackball";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_remotecontrol, TestSize.Level1)
{
    String deviceType = "remotecontrol";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_trackpad, TestSize.Level1)
{
    String deviceType = "trackpad";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_gamepad, TestSize.Level1)
{
    String deviceType = "gamepad";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_touchpad, TestSize.Level1)
{
    String deviceType = "touchpad";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_touchscreen, TestSize.Level1)
{
    String deviceType = "touchscreen";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CreateHandle_phone, TestSize.Level1)
{
    String deviceType = "phone";
    auto ret = VIRTUALDEVICETEST.CreateHandle(deviceType);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_SelectDevice_false01, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("argv1");
    fileList.push_back("argv2");
    fileList.push_back("argv3");
    auto ret = VIRTUALDEVICETEST.SelectDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_AddDevice_false01, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("hosmmi-vitual-device-manger ");
    fileList.push_back("start");
    auto ret = VIRTUALDEVICETEST.AddDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_AddDevice_true, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("binName ");
    fileList.push_back("start ");
    fileList.push_back("mouse");
    auto ret = VIRTUALDEVICETEST.AddDevice(fileList);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_SelectDevice_true, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("list");
    auto ret = VIRTUALDEVICETEST.SelectDevice(fileList);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_AddDevice_false02, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("binName ");
    fileList.push_back("start ");
    fileList.push_back("falseName");
    auto ret = VIRTUALDEVICETEST.AddDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CloseDevice_flase01, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("binName ");
    fileList.push_back("close ");
    auto ret = VIRTUALDEVICETEST.CloseDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CloseDevice_flase02, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("binName ");
    fileList.push_back("close ");
    fileList.push_back("falseArgv ");
    auto ret = VIRTUALDEVICETEST.CloseDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_listfalse01, TestSize.Level1)
{
    String firstArgv = "list";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("list");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_listfalse02, TestSize.Level1)
{
    String firstArgv = "list";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("list ");
    argvList.push_back("falseArgv");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_addFalse, TestSize.Level1)
{
    String firstArgv = "start";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("start ");
    argvList.push_back("falseArgv");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_addTrue, TestSize.Level1)
{
    String firstArgv = "start";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("start ");
    argvList.push_back("mouse");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_TRUE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_closeFalse01, TestSize.Level1)
{
    String firstArgv = "close";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("close ");
    argvList.push_back("falsePid");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_closeTrue01, TestSize.Level1)
{
    String symbolFileTest;
    symbolFileTest.append(OHOS::MMI::g_folderpath).append("1111111").append("_").append("testDevice");
    std::ofstream flagFile;
    flagFile.open(symbolFileTest.c_str());

    String firstArgv = "close";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("close ");
    argvList.push_back("1111111");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_mkdirFalse01, TestSize.Level1)
{
    String firstArgv = "close";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("close ");
    argvList.push_back("falsePid");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_FunctionalShunt_False01, TestSize.Level1)
{
    String firstArgv = "falseArgv";
    StringList argvList;
    argvList.push_back("binName ");
    argvList.push_back("falseArgv ");
    auto ret = VIRTUALDEVICETEST.FunctionalShunt(firstArgv, argvList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_SelectDevice_false02, TestSize.Level1)
{
    StringList fileList;
    String cmdStr = "rm -rf /data/symbol/*";
    system(cmdStr.c_str());
    auto ret = VIRTUALDEVICETEST.SelectDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_CloseDevice_false03, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("binName ");
    fileList.push_back("close ");
    fileList.push_back("falseArgv ");
    auto ret = VIRTUALDEVICETEST.CloseDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_SelectDevice_false03, TestSize.Level1)
{
    StringList fileList;
    String cmdStr = "rm -rf /data/symbol/";
    system(cmdStr.c_str());
    auto ret = VIRTUALDEVICETEST.SelectDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_AddDevice_false03, TestSize.Level1)
{
    StringList fileList;
    fileList.push_back("binName ");
    fileList.push_back("start ");
    fileList.push_back("mouse");
    auto ret = VIRTUALDEVICETEST.AddDevice(fileList);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_DoIoctl_false, TestSize.Level1)
{
    auto ret = VIRTUALDEVICETEST.DoIoctl(-1, UI_SET_KEYBIT, KEY_POWER);
    EXPECT_FALSE(ret);
}

HWTEST_F(VirtualDeviceTest, Test_SetUp_01, TestSize.Level1)
{
    auto ret = VIRTUALDEVICETEST.SetUp();
    EXPECT_TRUE(ret);
}
}