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

#include "processing_keyboard_device.h"
#include <gtest/gtest.h>
#include "proto.h"
#include "manage_inject_device.h"
#include "msg_head.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace std;
class ProcessingKeyboardDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(ProcessingKeyboardDeviceTest, Test_TransformKeyBoardJsonDataToInputData, TestSize.Level1)
{
    const string path = "/data/json/Test_TransformKeyBoardJsonDataToInputData.json";
    string startDeviceCmd = "mmi-virtual-device-manager start keyboard & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
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

HWTEST_F(ProcessingKeyboardDeviceTest, Test_TransformKeyBoardJsonDataToInputDataEventsIsEmpty, TestSize.Level1)
{
    const string path = "/data/json/Test_TransformKeyBoardJsonDataToInputDataEventsIsEmpty.json";
    string startDeviceCmd = "mmi-virtual-device-manager start keyboard & ";
    string closeDeviceCmd = "mmi-virtual-device-manager close all";
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
    system(startDeviceCmd.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace
