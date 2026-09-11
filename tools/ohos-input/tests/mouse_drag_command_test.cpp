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
#include "mouse_drag_command.h"
#include <climits>
#include <cstdint>
#include <vector>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;

class MouseDragCommandTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(MouseDragCommandTest, BuildDragSteps_ShortDuration_SingleTargetStep, TestSize.Level1)
{
    const DragPath path { 0, 0, 0, 0, 10, 10 };
    const auto steps = BuildDragSteps(1, path);
    EXPECT_EQ(steps.size(), 1U);
    EXPECT_EQ(steps[0].x, 10);
    EXPECT_EQ(steps[0].y, 10);
    EXPECT_EQ(steps[0].delayMs, 1);

    const auto sixteenMs = BuildDragSteps(16, path);
    EXPECT_EQ(sixteenMs.size(), 1U);
    EXPECT_EQ(sixteenMs[0].x, 10);
    EXPECT_EQ(sixteenMs[0].y, 10);
    EXPECT_EQ(sixteenMs[0].delayMs, 16);
}

HWTEST_F(MouseDragCommandTest, BuildDragSteps_SeventeenMs_SplitsIntoTwoSteps, TestSize.Level1)
{
    const DragPath path { 0, 0, 0, 0, 10, 10 };
    const auto steps = BuildDragSteps(17, path);
    EXPECT_EQ(steps.size(), 2U);
    EXPECT_EQ(steps[0].delayMs + steps[1].delayMs, 17);
    EXPECT_EQ(steps.back().x, 10);
    EXPECT_EQ(steps.back().y, 10);
}

HWTEST_F(MouseDragCommandTest, BuildDragSteps_StationaryPath_NoMoveStep, TestSize.Level1)
{
    const DragPath path { 0, 10, 10, 0, 10, 10 };
    const auto steps = BuildDragSteps(1, path);
    EXPECT_EQ(steps.size(), 1U);
    EXPECT_FALSE(steps[0].move);
    EXPECT_EQ(steps[0].delayMs, 1);
}

HWTEST_F(MouseDragCommandTest, BuildDragSteps_CrossDisplayPath_Moves, TestSize.Level1)
{
    const DragPath path { 0, 10, 10, 1, 10, 10 };
    const auto steps = BuildDragSteps(1, path);
    EXPECT_EQ(steps.size(), 1U);
    EXPECT_TRUE(steps[0].move);
}

HWTEST_F(MouseDragCommandTest, BuildDragSteps_ExtremeCoordinates_NoOverflow, TestSize.Level1)
{
    const DragPath path { 0, 0, 0, 0, INT32_MAX, INT32_MAX };
    const auto steps = BuildDragSteps(32, path);
    EXPECT_EQ(steps.size(), 2U);
    EXPECT_GT(steps[0].x, 0);
    EXPECT_GT(steps[0].y, 0);
    EXPECT_EQ(steps[1].x, INT32_MAX);
    EXPECT_EQ(steps[1].y, INT32_MAX);
    EXPECT_EQ(steps[0].delayMs, 16);
    EXPECT_EQ(steps[1].delayMs, 16);
}
