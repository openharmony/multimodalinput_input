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
#include "proto.h"
#define private public
#include "manage_inject_device.h"
#undef private
#include "msg_head.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace std;
class ManageInjectDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(ManageInjectDeviceTest, Test_TransformJsonDataCheckFileIsEmpty, TestSize.Level1)
{
    Json inputEventArrays;
    inputEventArrays.clear();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ManageInjectDeviceTest, Test_TransformJsonDataCheckFileNotEmpty, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformJsonDataCheckFileNotEmpty.json";
    string startDeviceCmd = "hosmmi-virtual-device-manager start all & ";
    string closeDeviceCmd = "hosmmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformJsonDataCheckFileNotEmpty.json";
    string startDeviceCmd = "./hosmmi-virtual-deviced.out start all &";
    string closeDeviceCmd = "./hosmmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(ManageInjectDeviceTest, Test_TransformJsonDataGetDeviceNodeError, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformJsonDataGetDeviceNodeError.json";
    string startDeviceCmd = "hosmmi-virtual-device-manager start all & ";
    string closeDeviceCmd = "hosmmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformJsonDataGetDeviceNodeError.json";
    string startDeviceCmd = "./hosmmi-virtual-deviced.out start all &";
    string closeDeviceCmd = "./hosmmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ManageInjectDeviceTest, Test_SendEventToHdi, TestSize.Level1)
{
    ManageInjectDevice manageInjectDevice;
    InputEventArray inputEventArray = {};
    auto ret = manageInjectDevice.SendEventToHdi(inputEventArray);
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ManageInjectDeviceTest, Test_SendEventToDeviveNodeError, TestSize.Level1)
{
    ManageInjectDevice manageInjectDevice;
    InputEventArray inputEventArray = {};
    inputEventArray.target = "";
    auto ret = manageInjectDevice.SendEventToDeviveNode(inputEventArray);
    EXPECT_EQ(ret, RET_ERR);
}
}