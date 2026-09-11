/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "command.h"
#include <string>
#include <vector>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;

class CommandTableTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(CommandTableTest, GetCommand_KnownPair_Found, TestSize.Level1)
{
    EXPECT_NE(GetCommand("key", "press"), nullptr);
    EXPECT_EQ(GetCommand("key", "unknown"), nullptr);
    EXPECT_EQ(GetCommand("unknown", "press"), nullptr);
}

HWTEST_F(CommandTableTest, GetCommand_MouseActions_NotRegistered, TestSize.Level1)
{
    EXPECT_EQ(GetCommand("mouse", "click"), nullptr);
    EXPECT_EQ(GetCommand("mouse", "double-click"), nullptr);
    EXPECT_EQ(GetCommand("mouse", "scroll"), nullptr);
    EXPECT_EQ(GetCommand("mouse", "move-to"), nullptr);
    EXPECT_EQ(GetCommand("mouse", "drag"), nullptr);
}

HWTEST_F(CommandTableTest, GetCommandsByDevice_ReturnsDeclarationOrder, TestSize.Level1)
{
    const auto commands = GetCommandsByDevice("key");
    const std::vector<std::string> expectedNames { "press" };
    ASSERT_EQ(commands.size(), expectedNames.size());
    for (size_t index = 0; index < commands.size(); ++index) {
        EXPECT_EQ(commands[index]->GetName(), expectedNames[index]);
    }
    EXPECT_TRUE(GetCommandsByDevice("mouse").empty());
}

HWTEST_F(CommandTableTest, GetCommand_RepeatedLookup_ReturnsSameObject, TestSize.Level1)
{
    const auto first = GetCommand("key", "press");
    const auto second = GetCommand("key", "press");
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first, second);
}
