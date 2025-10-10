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
#include <unistd.h>

#include "input_sendevent_command.h"
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputSendeventCommandTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Test_HandleSendEventCommand_01
 * @tc.desc: Test HandleSendEventCommand
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputSendeventCommandTest, Test_HandleSendEventCommand_01, TestSize.Level1)
{
    InputSendeventCommand command;
    const char* injectArgvs[] = { "uinput", "sendevent", "/dev/input/event0", "1", "2", "3" };
    char** argv = const_cast<char**>(injectArgvs);
    optind = 1;
    EXPECT_EQ(command.HandleSendEventCommand(5, argv), RET_ERR);
    optind = 1;
    EXPECT_EQ(command.HandleSendEventCommand(6, argv), RET_OK);
}

/**
 * @tc.name: Test_SendEventOption_01
 * @tc.desc: Test SendEventOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputSendeventCommandTest, Test_SendEventOption_01, TestSize.Level1)
{
    InputSendeventCommand command;
    const char* injectArgvs[] = { "uinput", "sendevent", "/dev/input/event0", "1", "2", "3" };
    char** argv = const_cast<char**>(injectArgvs);
    injectArgvs[2] = "";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[2] = "/dev/input/eventX";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[2] = "/dev/input/event0";
    optind = 1;
    EXPECT_TRUE(command.SendEventOption(6, argv));
}

/**
 * @tc.name: Test_SendEventOption_02
 * @tc.desc: Test SendEventOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputSendeventCommandTest, Test_SendEventOption_02, TestSize.Level1)
{
    InputSendeventCommand command;
    const char* injectArgvs[] = { "uinput", "sendevent", "/dev/input/event0", "1", "2", "3" };
    char** argv = const_cast<char**>(injectArgvs);
    injectArgvs[3] = "655365";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[3] = "65536";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[3] = "abc";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[3] = "1";
    optind = 1;
    EXPECT_TRUE(command.SendEventOption(6, argv));
}

/**
 * @tc.name: Test_SendEventOption_03
 * @tc.desc: Test SendEventOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputSendeventCommandTest, Test_SendEventOption_03, TestSize.Level1)
{
    InputSendeventCommand command;
    const char* injectArgvs[] = { "uinput", "sendevent", "/dev/input/event0", "1", "2", "3" };
    char** argv = const_cast<char**>(injectArgvs);
    injectArgvs[4] = "655365";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[4] = "65536";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[4] = "abc";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[4] = "2";
    optind = 1;
    EXPECT_TRUE(command.SendEventOption(6, argv));
}

/**
 * @tc.name: Test_SendEventOption_04
 * @tc.desc: Test SendEventOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputSendeventCommandTest, Test_SendEventOption_04, TestSize.Level1)
{
    InputSendeventCommand command;
    const char* injectArgvs[] = { "uinput", "sendevent", "/dev/input/event0", "1", "2", "3" };
    char** argv = const_cast<char**>(injectArgvs);
    injectArgvs[5] = "214748364910";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[5] = "-2147483649";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[5] = "2147483649";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[5] = "abc";
    optind = 1;
    EXPECT_FALSE(command.SendEventOption(6, argv));
    injectArgvs[5] = "3";
    optind = 1;
    EXPECT_TRUE(command.SendEventOption(6, argv));
}

/**
 * @tc.name: Test_RunSendEvent_01
 * @tc.desc: Test RunSendEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputSendeventCommandTest, Test_RunSendEvent_01, TestSize.Level1)
{
    InputSendeventCommand command;
    command.injectArgvs_ = { "sendevent", "/dev/input/eventX", "1", "2", "3", "4" };
    EXPECT_EQ(command.RunSendEvent(), RET_ERR);
    command.injectArgvs_ = { "sendevent", "", "1", "2", "3" };
    EXPECT_EQ(command.RunSendEvent(), RET_ERR);
    command.injectArgvs_ = { "sendevent", "/dev/input/eventX", "1", "2", "3" };
    EXPECT_EQ(command.RunSendEvent(), RET_ERR);
    command.injectArgvs_ = { "sendevent", "/dev/input/event0", "1", "2", "3" };
    EXPECT_EQ(command.RunSendEvent(), RET_OK);
}

} // namespace MMI
} // namespace OHOS