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

#include "manage_inject_device.h"
#include "msg_head.h"
#include "processing_game_pad_device.h"
#include "proto.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace
class ProcessingGamePadDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:Test_TransformGamePadJsonDataToInputData
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputData, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformGamePadJsonDataToInputData.json";
    std::string startDeviceCmd = "vuinput start gamepad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::string jsonBuf = ReadJsonFile(path);
    if (jsonBuf.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuf, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name:Test_TransformGamePadJsonDataToInputDataNotFindEvents
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindEvents, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindEvents.json";
    std::string startDeviceCmd = "vuinput start gamepad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::string jsonBuf = ReadJsonFile(path);
    if (jsonBuf.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuf, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:Test_TransformGamePadJsonDataToInputDataEventsIsEmpty
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataEventsIsEmpty, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformGamePadJsonDataToInputDataEventsIsEmpty.json";
    std::string startDeviceCmd = "vuinput start gamepad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::string jsonBuf = ReadJsonFile(path);
    if (jsonBuf.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuf, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:Test_TransformGamePadJsonDataToInputDataNotFindKeyValueInPress
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindKeyValueInPress, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindKeyValueInPress.json";
    std::string startDeviceCmd = "vuinput start gamepad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::string jsonBuf = ReadJsonFile(path);
    if (jsonBuf.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuf, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:Test_TransformGamePadJsonDataToInputDataNotFindEventInRocker
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindEventInRocker, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindEventInRocker.json";
    std::string startDeviceCmd = "vuinput start gamepad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::string jsonBuf = ReadJsonFile(path);
    if (jsonBuf.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuf, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRocker
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRocker, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRocker.json";
    std::string startDeviceCmd = "vuinput start gamepad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::string jsonBuf = ReadJsonFile(path);
    if (jsonBuf.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuf, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRockerDirectionKey
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingGamePadDeviceTest, Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRockerDirectionKey,
         TestSize.Level1)
{
    const std::string path =
     "/data/json/Test_TransformGamePadJsonDataToInputDataNotFindDirectionInRockerDirectionKey.json";
    std::string startDeviceCmd = "vuinput start gamepad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::string jsonBuf = ReadJsonFile(path);
    if (jsonBuf.empty()) {
        ASSERT_TRUE(false) << "Read file failed" << path;
    }
    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonBuf, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS