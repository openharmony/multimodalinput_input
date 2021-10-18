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
#include "processing_touch_screen_device.h"
#include "manage_inject_device.h"
#include "msg_head.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace std;
class ProcessingTouchScreenDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(ProcessingTouchScreenDeviceTest, Test_TransformJsonDataToInputData, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformTouchScreenJsonDataToInputData.json";
    string startDeviceCmd = "hosmmi-virtual-device-manager start touchscreen & ";
    string closeDeviceCmd = "hosmmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformTouchScreenJsonDataToInputData.json";
    string startDeviceCmd = "./hosmmi-virtual-deviced.out start touchscreen &";
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

HWTEST_F(ProcessingTouchScreenDeviceTest, Test_TransformJsonDataToInputDataEventsIsEmpty, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformJsonDataToInputDataEventsIsEmpty.json";
    string startDeviceCmd = "hosmmi-virtual-device-manager start touchscreen & ";
    string closeDeviceCmd = "hosmmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformJsonDataToInputDataEventsIsEmpty.json";
    string startDeviceCmd = "./hosmmi-virtual-deviced.out start touchscreen &";
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

HWTEST_F(ProcessingTouchScreenDeviceTest, Test_TransformJsonDataToInputDataSingleEventsIsEmpty, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformJsonDataToInputDataSingleEventsIsEmpty.json";
    string startDeviceCmd = "hosmmi-virtual-device-manager start touchscreen & ";
    string closeDeviceCmd = "hosmmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformJsonDataToInputDataSingleEventsIsEmpty.json";
    string startDeviceCmd = "./hosmmi-virtual-deviced.out start touchscreen &";
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
}