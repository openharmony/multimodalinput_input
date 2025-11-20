/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "manage_inject_device.h"
#include "msg_head.h"
#include "processing_pen_device.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class ProcessingPenDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static void CheckJsonData(const std::string path)
    {
        std::string startDeviceCmd = "vuinput start touchpad & ";
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
};

/**
 * @tc.name:Test_TransformPenJsonDataToInputData
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputData.json";
    std::string startDeviceCmd = "vuinput start touchpad & ";
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
 * @tc.name:Test_TransformPenJsonDataToInputDataNotfindEvents
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputDataNotfindEvents, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputDataNotfindEvents.json";
    CheckJsonData(path);
}

/**
 * @tc.name:Test_TransformPenJsonDataToInputDataEventsIsEmpty
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputDataEventsIsEmpty, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputDataEventsIsEmpty.json";
    CheckJsonData(path);
}

/**
 * @tc.name:Test_TransformPenJsonDataToInputDataApproachEventError
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputDataApproachEventError, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputDataApprochEventError.json";
    CheckJsonData(path);
}

/**
 * @tc.name:Test_TransformPenJsonDataToInputDataSlideEventError
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputDataSlideEventError, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputDataSlideEventError.json";
    CheckJsonData(path);
}

/**
 * @tc.name:Test_TransformPenJsonDataToInputDataLeaveEventError
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputDataLeaveEventError, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputDataLeaveEventError.json";
    CheckJsonData(path);
}

/**
 * @tc.name:Test_TransformPenJsonDataToInputDataApproachEventEventTypeError
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputDataApproachEventEventTypeError, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputDataApprochEventEventTypeError.json";
    CheckJsonData(path);
}

/**
 * @tc.name:Test_TransformPenJsonDataToInputDataLeaveEventEventTypeError
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputDataLeaveEventEventTypeError, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformPenJsonDataToInputDataLeaveEventEventTypeError.json";
    CheckJsonData(path);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_InvalidDeviceIndex
 * @tc.desc: Verify behavior when using invalid device index for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_InvalidDeviceIndex, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "pen",
            "deviceIndex": -1,
            "events": [
                [[100, 200]]
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_WrongDeviceName
 * @tc.desc: Verify behavior when using wrong device name for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_WrongDeviceName, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "keyboard",
            "deviceIndex": 0,
            "events": [
                [[100, 200]]
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_MultipleTouchPoints
 * @tc.desc: Verify behavior with multiple touch points for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_MultipleTouchPoints, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "pen",
            "deviceIndex": 0,
            "events": [
                [[100, 200], [300, 400], [500, 600]]
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_ObjectEventType
 * @tc.desc: Verify behavior with object event type for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_ObjectEventType, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "pen",
            "deviceIndex": 0,
            "events": [
                {
                    "eventType": "touch",
                    "xPos": 100,
                    "yPos": 200,
                    "pressure": 255,
                    "tiltX": 10,
                    "tiltY": 20
                }
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_MixedEventTypes
 * @tc.desc: Verify behavior with mixed event types for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_MixedEventTypes, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "pen",
            "deviceIndex": 0,
            "events": [
                [[100, 200]],
                {
                    "eventType": "touch",
                    "xPos": 300,
                    "yPos": 400,
                    "pressure": 128
                }
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_InvalidCoordinates
 * @tc.desc: Verify behavior with invalid coordinates for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_InvalidCoordinates, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "pen",
            "deviceIndex": 0,
            "events": [
                [["invalid", 200]]
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_EmptyJsonData
 * @tc.desc: Verify behavior with empty JSON data for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_EmptyJsonData, TestSize.Level1)
{
    const std::string jsonData = "";
    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_InvalidJsonFormat
 * @tc.desc: Verify behavior with invalid JSON format for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_InvalidJsonFormat, TestSize.Level1)
{
    const std::string jsonData = R"({ invalid json })";
    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_ZeroCoordinates
 * @tc.desc: Verify behavior with zero coordinates for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_ZeroCoordinates, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "pen",
            "deviceIndex": 0,
            "events": [
                [[0, 0]]
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Test_TransformPenJsonDataToInputData_NegativeCoordinates
 * @tc.desc: Verify behavior with negative coordinates for pen device processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingPenDeviceTest, Test_TransformPenJsonDataToInputData_NegativeCoordinates, TestSize.Level1)
{
    const std::string jsonData = R"([
        {
            "deviceName": "pen",
            "deviceIndex": 0,
            "events": [
                [[-100, -200]]
            ]
        }
    ])";

    std::string startDeviceCmd = "vuinput start touchpad & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Start device failed";
    }
    pclose(startDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    ManageInjectDevice manageInjectDevice;
    auto ret = manageInjectDevice.TransformJsonData(DataInit(jsonData, false));
    FILE* closeDevice = popen(closeDeviceCmd.c_str(), "rw");
    if (!closeDevice) {
        ASSERT_TRUE(false) << "Close device failed";
    }
    pclose(closeDevice);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS
