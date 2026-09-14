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

HWTEST_F(CommandTableTest, GetCommand_KnownName_Found, TestSize.Level1)
{
    EXPECT_NE(GetCommand("mouse-click"), nullptr);
    EXPECT_EQ(GetCommand("unknown"), nullptr);
}

HWTEST_F(CommandTableTest, GetCommand_AllKnownNames_Found, TestSize.Level1)
{
    const std::vector<std::string> expectedNames {
        "mouse-click", "mouse-double-click", "mouse-scroll", "mouse-move", "mouse-drag", "key-press"
    };
    for (const auto &name : expectedNames) {
        EXPECT_NE(GetCommand(name), nullptr) << name << " not registered";
    }
}

HWTEST_F(CommandTableTest, GetCommand_RepeatedLookup_ReturnsSameObject, TestSize.Level1)
{
    const auto first = GetCommand("key-press");
    const auto second = GetCommand("key-press");
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first, second);
}
