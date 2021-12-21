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
#include "expansibility_operation.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class ExpansiBilityOperationTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(ExpansiBilityOperationTest, registDeviceEventFD_001, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = 0;
    retResult = expansibilityOperation.RegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, registDeviceEventFD_002, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = 100000;
    retResult = expansibilityOperation.RegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, registDeviceEventFD_003, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = -1;
    retResult = expansibilityOperation.RegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, registDeviceEventFD_004, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = -100000;
    retResult = expansibilityOperation.RegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, unRegistDeviceEventFD_001, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = 0;
    retResult = expansibilityOperation.UnRegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, unRegistDeviceEventFD_002, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = 10000;
    retResult = expansibilityOperation.UnRegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, unRegistDeviceEventFD_003, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = -10000;
    retResult = expansibilityOperation.UnRegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, unRegistDeviceEventFD_004, TestSize.Level1)
{
    bool retResult = false;
    ExpansibilityOperation expansibilityOperation;
    int32_t deviceEventFD = -1;
    retResult = expansibilityOperation.UnRegistDeviceEventFd(deviceEventFD);
    EXPECT_TRUE(retResult);
}

HWTEST_F(ExpansiBilityOperationTest, LoadExteralLibrary, TestSize.Level1)
{
    ExpansibilityOperation expansibilityOperation;
    const std::string cfg = "cfg";
    const std::string libPath = "libPath";
    expansibilityOperation.LoadExteralLibrary(cfg, libPath);
}

HWTEST_F(ExpansiBilityOperationTest, LoadExteralLibrary_001, TestSize.Level1)
{
    ExpansibilityOperation expansibilityOperation;
    const std::string cfg = "";
    const std::string libPath = "libPath";
    expansibilityOperation.LoadExteralLibrary(cfg, libPath);
}

HWTEST_F(ExpansiBilityOperationTest, LoadExteralLibrary_002, TestSize.Level1)
{
    ExpansibilityOperation expansibilityOperation;
    const std::string cfg = "cfg";
    const std::string libPath = "";
    expansibilityOperation.LoadExteralLibrary(cfg, libPath);
}

HWTEST_F(ExpansiBilityOperationTest, LoadExteralLibrary_003, TestSize.Level1)
{
    ExpansibilityOperation expansibilityOperation;
    const std::string cfg = "";
    const std::string libPath = "";
    expansibilityOperation.LoadExteralLibrary(cfg, libPath);
}
} // namespace
