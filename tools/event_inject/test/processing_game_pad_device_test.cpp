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

#include "processing_game_pad_device.h"
#include <gtest/gtest.h>
#include "manage_inject_device.h"
#include "msg_head.h"
#include "proto.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace std;
class ProcessingGamePadDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputData, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformGamePadJsonDataToInputData.json";
    string startDeviceCmd = "mmi-virtual-device-manager start gamepad & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformGamePadJsonDataToInputData.json";
    string startDeviceCmd = "./mmi-virtual-deviced.out start gamepad &";
    string closeDeviceCmd = "./mmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    if (!reader.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system(closeDeviceCmd.c_str());
        ASSERT_TRUE(false) << "can not open " << path;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindEvents, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindEvents.json";
    string startDeviceCmd = "mmi-virtual-device-manager start gamepad & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformGamePadJsonDataToInputDataNotFindEvents.json";
    string startDeviceCmd = "./mmi-virtual-deviced.out start gamepad &";
    string closeDeviceCmd = "./mmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    if (!reader.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system(closeDeviceCmd.c_str());
        ASSERT_TRUE(false) << "can not open " << path;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataEventsIsEmpty, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformGamePadJsonDataToInputDataEventsIsEmpty.json";
    string startDeviceCmd = "mmi-virtual-device-manager start gamepad & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformGamePadJsonDataToInputDataEventsIsEmpty.json";
    string startDeviceCmd = "./mmi-virtual-deviced.out start gamepad &";
    string closeDeviceCmd = "./mmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    if (!reader.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system(closeDeviceCmd.c_str());
        ASSERT_TRUE(false) << "can not open " << path;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindKeyValueInPress, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindKeyValueInPress.json";
    string startDeviceCmd = "mmi-virtual-device-manager start gamepad & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformGamePadJsonDataToInputDataNotFindKeyValueInPress.json";
    string startDeviceCmd = "./mmi-virtual-deviced.out start gamepad &";
    string closeDeviceCmd = "./mmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    if (!reader.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system(closeDeviceCmd.c_str());
        ASSERT_TRUE(false) << "can not open " << path;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindEventInRocker, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindEventInRocker.json";
    string startDeviceCmd = "mmi-virtual-device-manager start gamepad & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformGamePadJsonDataToInputDataNotFindEventInRocker.json";
    string startDeviceCmd = "./mmi-virtual-deviced.out start gamepad &";
    string closeDeviceCmd = "./mmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    if (!reader.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system(closeDeviceCmd.c_str());
        ASSERT_TRUE(false) << "can not open " << path;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRocker, TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRocker.json";
    string startDeviceCmd = "mmi-virtual-device-manager start gamepad & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRocker.json";
    string startDeviceCmd = "./mmi-virtual-deviced.out start gamepad &";
    string closeDeviceCmd = "./mmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    if (!reader.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system(closeDeviceCmd.c_str());
        ASSERT_TRUE(false) << "can not open " << path;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_ERR);
}

HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRockerDirectionKey,
         TestSize.Level1)
{
#ifdef OHOS_BUILD
    const string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRockerDirectionKey.json";
    string startDeviceCmd = "mmi-virtual-device-manager start gamepad & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
#else
    const string path = "temp/Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRockerDirectionKey.json";
    string startDeviceCmd = "./mmi-virtual-deviced.out start gamepad &";
    string closeDeviceCmd = "./mmi-virtual-deviced.out close all";
#endif
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::ifstream reader(path);
    if (!reader.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        system(closeDeviceCmd.c_str());
        ASSERT_TRUE(false) << "can not open " << path;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(inputEventArrays);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    system(closeDeviceCmd.c_str());
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace