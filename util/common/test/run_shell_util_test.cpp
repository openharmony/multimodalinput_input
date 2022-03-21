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

#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "run_shell_util.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;
constexpr int32_t SLEEP = 1000;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "RunShellUtilTest" };
} // namespace

class RunShellUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
    }
    static inline RunShellUtil runCommand;
};

/**
 * @tc.name:RunShellUtilTest_RunShellCommand_001
 * @tc.desc:Verify run shell command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RunShellUtilTest, RunShellUtilTest_RunShellCommand_001, TestSize.Level1)
{
    std::string command = "test runshellutil";
    std::vector<std::string> firstLog;
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
    ASSERT_TRUE(runCommand.RunShellCommand(command, firstLog) == RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
    MMI_LOGD("test runshellutilrqr2qrq2");
    std::vector<std::string> vLog;
    ASSERT_TRUE(runCommand.RunShellCommand(command, vLog) == RET_OK);
    ASSERT_FALSE(vLog.empty());
    if (firstLog.empty()) {
        EXPECT_TRUE(vLog.size() > firstLog.size());
        EXPECT_TRUE(vLog.back().find(command) != vLog.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(vLog.back().c_str(), firstLog.back().c_str()) != 0);
    }
}

/**
 * @tc.name:RunShellUtilTest_RunShellCommand_002
 * @tc.desc:Verify run shell command
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RunShellUtilTest, RunShellUtilTest_RunShellCommand_002, TestSize.Level1)
{
    std::string command = "test runshellutil";
    {
        std::vector<std::string> firstLog;
        ASSERT_TRUE(runCommand.RunShellCommand(command, firstLog) == RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
        MMI_LOGD("test runshellutilrqr2342342355qrq2");
        std::vector<std::string> vLog;
        ASSERT_TRUE(runCommand.RunShellCommand(command, vLog) == RET_OK);
        ASSERT_FALSE(vLog.empty());
        if (firstLog.empty()) {
            EXPECT_TRUE(vLog.size() > firstLog.size());
            EXPECT_TRUE(vLog.back().find(command) != vLog.back().npos);
        } else {
            EXPECT_TRUE(std::strcmp(vLog.back().c_str(), firstLog.back().c_str()) != 0);
        }
    }
    std::vector<std::string> firstLog;
    ASSERT_TRUE(runCommand.RunShellCommand(command, firstLog) == RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP));
    MMI_LOGD("test runshellutilrqr21234www");
    std::vector<std::string> vLog;
    ASSERT_TRUE(runCommand.RunShellCommand(command, vLog) == RET_OK);
    ASSERT_FALSE(vLog.empty());
    if (firstLog.empty()) {
        EXPECT_TRUE(vLog.size() > firstLog.size());
        EXPECT_TRUE(vLog.back().find(command) != vLog.back().npos);
    } else {
        EXPECT_TRUE(std::strcmp(vLog.back().c_str(), firstLog.back().c_str()) != 0);
    }
}
} // namespace MMI
} // namespace OHOS