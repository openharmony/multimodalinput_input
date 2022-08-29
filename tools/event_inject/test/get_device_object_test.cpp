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

#include "get_device_object.h"
#include "manage_inject_device.h"
#include "msg_head.h"
#include "proto.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class GetDeviceObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:Test_GetDeviceObjectTest
 * @tc.desc:Verify TransformJsonData function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetDeviceObjectTest, Test_GetDeviceObjectTest, TestSize.Level1)
{
    const std::string path = "/data/json/Test_GetDeviceObjectTest.json";
    std::string startDeviceCmd = "vuinput start all & ";
    std::string closeDeviceCmd = "vuinput close all";
    FILE* startDevice = popen(startDeviceCmd.c_str(), "rw");
    if (!startDevice) {
        ASSERT_TRUE(false) << "Can not failed";
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
 * @tc.name:Test_GetDeviceObjectTestNotFindDevice
 * @tc.desc:Verify CreateDeviceObject function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetDeviceObjectTest, Test_GetDeviceObjectTestNotFindDevice, TestSize.Level1)
{
    const std::string deviceName = "temp";
    bool result;
    auto ret = GetDeviceObject::CreateDeviceObject(deviceName);
    if (ret == nullptr) {
        result = true;
    } else {
        result = false;
    }
    EXPECT_EQ(result, true);
}
} // namespace MMI
} // namespace OHOS