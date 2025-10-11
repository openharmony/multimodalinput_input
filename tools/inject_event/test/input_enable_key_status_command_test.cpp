/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <unistd.h>

#include "define_multimodal.h"
#include "input_enable_key_status_command.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputEnableKeyStatusCommandTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Test_HandleEnableKeyStatusCommand_01
 * @tc.desc: Test HandleEnableKeyStatusCommand
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEnableKeyStatusCommandTest, Test_HandleEnableKeyStatusCommand_01, TestSize.Level1)
{
    InputEnableKeyStatusCommand command;
    const char* injectArgvs[] = { "uinput", "enable_key_status", "1", "5"};
    char** argv = const_cast<char**>(injectArgvs);
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(2, argv), RET_ERR);
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(5, argv), RET_ERR);
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(4, argv), RET_OK);
    injectArgvs[3] = "";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(4, argv), RET_ERR);
    injectArgvs[3] = "0";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(4, argv), RET_ERR);
    injectArgvs[3] = "1";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(4, argv), RET_OK);
    injectArgvs[3] = "11";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(4, argv), RET_ERR);
    injectArgvs[3] = "abc";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(4, argv), RET_ERR);
}

/**
 * @tc.name: Test_HandleEnableKeyStatusCommand_02
 * @tc.desc: Test HandleEnableKeyStatusCommand
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEnableKeyStatusCommandTest, Test_HandleEnableKeyStatusCommand_02, TestSize.Level1)
{
    InputEnableKeyStatusCommand command;
    const char* injectArgvs[] = { "uinput", "enable_key_status", "0"};
    char** argv = const_cast<char**>(injectArgvs);
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(2, argv), RET_ERR);
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(5, argv), RET_ERR);
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(3, argv), RET_OK);
    injectArgvs[2] = "";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(3, argv), RET_ERR);
    injectArgvs[2] = "2";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(3, argv), RET_ERR);
    injectArgvs[2] = "abc";
    optind = 1;
    EXPECT_EQ(command.HandleEnableKeyStatusCommand(3, argv), RET_ERR);
}

/**
 * @tc.name: Test_RunEnableKeyStatus_01
 * @tc.desc: Test RunEnableKeyStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEnableKeyStatusCommandTest, Test_RunEnableKeyStatus_01, TestSize.Level1)
{
    InputEnableKeyStatusCommand command;
    command.injectArgvs_.clear();
    EXPECT_EQ(command.RunEnableKeyStatus(), RET_ERR);
}
} // namespace MMI
} // namespace OHOS