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
#include "mouse_support.h"
#include <cstdint>
#include <string>

#include "pointer_event.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;

class MouseSupportTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(MouseSupportTest, ValidateScrollClicks_ValidRange_Accepted, TestSize.Level1)
{
    const int32_t valid[] = { 1, 100, -1, -100 };
    for (int32_t clicks : valid) {
        std::string error;
        EXPECT_TRUE(ValidateScrollClicks(clicks, error));
    }
}

HWTEST_F(MouseSupportTest, ValidateScrollClicks_ZeroAndBeyondRange_Rejected, TestSize.Level1)
{
    const int32_t invalid[] = { 0, 101, -101 };
    for (int32_t clicks : invalid) {
        std::string error;
        EXPECT_FALSE(ValidateScrollClicks(clicks, error));
        EXPECT_FALSE(error.empty());
    }
}

HWTEST_F(MouseSupportTest, ParseButton_NamedButtons_MapToCodes, TestSize.Level1)
{
    struct ButtonCase {
        const char *value;
        int32_t code;
    };
    const ButtonCase cases[] = {
        { "left", OHOS::MMI::PointerEvent::MOUSE_BUTTON_LEFT },
        { "right", OHOS::MMI::PointerEvent::MOUSE_BUTTON_RIGHT },
        { "middle", OHOS::MMI::PointerEvent::MOUSE_BUTTON_MIDDLE },
    };
    for (const ButtonCase &testCase : cases) {
        Options options { { "--button", testCase.value } };
        int32_t button = -1;
        std::string error;
        EXPECT_TRUE(ParseButton(options, button, error));
        EXPECT_EQ(button, testCase.code);
    }
}

HWTEST_F(MouseSupportTest, ParseButton_Absent_DefaultsToLeft, TestSize.Level1)
{
    Options options;
    int32_t button = -1;
    std::string error;
    EXPECT_TRUE(ParseButton(options, button, error));
    EXPECT_EQ(button, OHOS::MMI::PointerEvent::MOUSE_BUTTON_LEFT);
}

HWTEST_F(MouseSupportTest, ParseButton_Unknown_Rejected, TestSize.Level1)
{
    Options options { { "--button", "diag" } };
    int32_t button = -1;
    std::string error;
    EXPECT_FALSE(ParseButton(options, button, error));
    EXPECT_FALSE(error.empty());
}
