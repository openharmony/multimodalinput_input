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
#include "modifier.h"
#include <cstdint>
#include <string>
#include <vector>

#include "key_event.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;
using OHOS::MMI::KeyEvent;

class ModifierTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(ModifierTest, ParseModifiers_TwoKeys_KeepsGivenOrder, TestSize.Level1)
{
    std::vector<int32_t> modifiers;
    std::string error;
    EXPECT_TRUE(ParseModifiers("shift|ctrl", modifiers, error));
    EXPECT_EQ(modifiers.size(), 2U);
    EXPECT_EQ(modifiers[0], KeyEvent::KEYCODE_SHIFT_LEFT);
    EXPECT_EQ(modifiers[1], KeyEvent::KEYCODE_CTRL_LEFT);
}

HWTEST_F(ModifierTest, ParseModifiers_SingleKey_MapsToKeyCode, TestSize.Level1)
{
    struct ModifierCase {
        const char *name;
        int32_t key;
    };
    const ModifierCase cases[] = {
        { "ctrl", KeyEvent::KEYCODE_CTRL_LEFT },
        { "alt", KeyEvent::KEYCODE_ALT_LEFT },
        { "shift", KeyEvent::KEYCODE_SHIFT_LEFT },
        { "meta", KeyEvent::KEYCODE_META_LEFT },
    };
    for (const ModifierCase &testCase : cases) {
        std::vector<int32_t> modifiers;
        std::string error;
        EXPECT_TRUE(ParseModifiers(testCase.name, modifiers, error));
        EXPECT_EQ(modifiers.size(), 1U);
        EXPECT_EQ(modifiers[0], testCase.key);
    }
}

HWTEST_F(ModifierTest, ParseModifiers_Malformed_RejectedWithMessage, TestSize.Level1)
{
    const char *values[] = { "", "|ctrl", "ctrl|", "ctrl||shift", "unknown" };
    for (const char *value : values) {
        std::vector<int32_t> modifiers;
        std::string error;
        EXPECT_FALSE(ParseModifiers(value, modifiers, error));
        EXPECT_FALSE(error.empty());
    }
}

HWTEST_F(ModifierTest, ParseModifiers_Duplicate_RejectedWithMessage, TestSize.Level1)
{
    std::vector<int32_t> modifiers;
    std::string error;
    EXPECT_FALSE(ParseModifiers("ctrl|ctrl", modifiers, error));
    EXPECT_FALSE(error.empty());
}
