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
#include "input_manager.h"
#include "input_manager_command.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace std;
class InjectEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:InjectEvent_InjectMouse_001
 * @tc.desc: test inject mouse move interface
 * @tc.type: FUNC
 * @tc.require: AR000GJN3F
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectMouse_001, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-M"};
    char command3[] = {"-m"};
    char command4[] = {"10"};
    char command5[] = {"12"};
    char *argv[] = {command1, command2, command3, command4, command5};
    int32_t result = inputManagerCommand->ParseCommand(5, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectMouse_002
 * @tc.desc: test inject mouse down interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectMouse_002, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-M"};
    char command3[] = {"-d"};
    char command4[] = {"1"};
    char *argv[] = {command1, command2, command3, command4};
    int32_t result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectMouse_003
 * @tc.desc: test inject mouse scroll interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectMouse_003, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-M"};
    char command3[] = {"-s"};
    char command4[] = {"50"};
    char *argv[] = {command1, command2, command3, command4};
    int32_t result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectMouse_004
 * @tc.desc: test inject mouse click interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectMouse_004, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-M"};
    char command3[] = {"-c"};
    char command4[] = {"1"};
    char *argv[] = {command1, command2, command3, command4};
    int32_t result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectMouse_005
 * @tc.desc: test inject mouse up interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectMouse_005, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-M"};
    char command3[] = {"-u"};
    char command4[] = {"1"};
    char *argv[] = {command1, command2, command3, command4};
    int32_t result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectKey_001
 * @tc.desc: test inject key down interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectKey_001, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-K"};
    char command3[] = {"-d"};
    char command4[] = {"1"};
    char *argv[] = {command1, command2, command3, command4};
    int32_t result = inputManagerCommand->ParseCommand(4, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectKey_002
 * @tc.desc: test inject key down interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectKey_002, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-K"};
    char command3[] = {"-d"};
    char command4[] = {"1"};
    char command5[] = {"-d"};
    char command6[] = {"2"};
    char *argv[] = {command1, command2, command3, command4, command5, command6};
    int32_t result = inputManagerCommand->ParseCommand(6, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectKey_003
 * @tc.desc: test inject key up interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectKey_003, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-K"};
    char command3[] = {"-d"};
    char command4[] = {"1"};
    char command5[] = {"-u"};
    char command6[] = {"1"};
    char *argv[] = {command1, command2, command3, command4, command5, command6};
    int32_t result = inputManagerCommand->ParseCommand(6, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectTouch_001
 * @tc.desc: test inject touch move interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectTouch_001, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-T"};
    char command3[] = {"-m"};
    char command4[] = {"10"};
    char command5[] = {"12"};
    char command6[] = {"13"};
    char command7[] = {"14"};
    char *argv[] = {command1, command2, command3, command4, command5, command6, command7};
    int32_t result = inputManagerCommand->ParseCommand(7, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectTouch_002
 * @tc.desc: test inject touch down interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectTouch_002, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-T"};
    char command3[] = {"-m"};
    char command4[] = {"10"};
    char command5[] = {"12"};
    char *argv[] = {command1, command2, command3, command4, command5};
    int32_t result = inputManagerCommand->ParseCommand(5, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}

/**
 * @tc.name:InjectEvent_InjectTouch_003
 * @tc.desc: test inject touch up interface
 * @tc.type: FUNC
 * @tc.require: SR000GGQBJ
 */
HWTEST_F(InjectEventTest, InjectEvent_InjectTouch_003, TestSize.Level1)
{
    std::unique_ptr<InputManagerCommand> inputManagerCommand = std::make_unique<InputManagerCommand>();
    char command1[] = {"input"};
    char command2[] = {"-T"};
    char command3[] = {"-u"};
    char command4[] = {"10"};
    char command5[] = {"12"};
    char *argv[] = {command1, command2, command3, command4, command5};
    int32_t result = inputManagerCommand->ParseCommand(5, argv);
    EXPECT_EQ(OHOS::ERR_OK, result);
}
}