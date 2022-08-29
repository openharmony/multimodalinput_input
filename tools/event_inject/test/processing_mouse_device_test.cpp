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
#include "processing_keyboard_device.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class ProcessingMouseDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:Test_TransformJsonDataToInputData
 * @tc.desc:Verify ManageInjectDevice function TransformJsonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessingMouseDeviceTest, Test_TransformJsonDataToInputData, TestSize.Level1)
{
    const std::string path = "/data/json/Test_TransformMouseJsonDataToInputData.json";
    std::string startDeviceCmd = "vuinput start mouse & ";
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
} // namespace MMI
} // namespace OHOS