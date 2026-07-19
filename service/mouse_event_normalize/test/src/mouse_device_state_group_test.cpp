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

#include "mouse_device_state.h"
#include "window_info.h"

using namespace testing::ext;

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t GROUP_A = 1;
constexpr int32_t GROUP_B = 2;
constexpr uint32_t BTN_LEFT_CODE = 0x110;
} // namespace

class MouseDeviceStateGroupTest : public testing::Test {
protected:
    void SetUp() override
    {
        MouseState->RemoveGroupState(GROUP_A);
        MouseState->RemoveGroupState(GROUP_B);
    }

    void TearDown() override
    {
        MouseState->RemoveGroupState(GROUP_A);
        MouseState->RemoveGroupState(GROUP_B);
    }
};

HWTEST_F(MouseDeviceStateGroupTest, DefaultGroupUsesGlobalState_001, TestSize.Level1)
{
    MouseState->SetMouseCoords(DEFAULT_GROUP_ID, 100, 200);
    EXPECT_EQ(MouseState->GetMouseCoordsX(DEFAULT_GROUP_ID), 100);
    EXPECT_EQ(MouseState->GetMouseCoordsY(DEFAULT_GROUP_ID), 200);
    EXPECT_EQ(MouseState->GetMouseCoordsX(), 100);
    EXPECT_EQ(MouseState->GetMouseCoordsY(), 200);
}

HWTEST_F(MouseDeviceStateGroupTest, NonDefaultGroupIsolated_001, TestSize.Level1)
{
    MouseState->SetMouseCoords(DEFAULT_GROUP_ID, 100, 200);
    MouseState->SetMouseCoords(GROUP_A, 300, 400);
    MouseState->SetMouseCoords(GROUP_B, 500, 600);

    EXPECT_EQ(MouseState->GetMouseCoordsX(DEFAULT_GROUP_ID), 100);
    EXPECT_EQ(MouseState->GetMouseCoordsY(DEFAULT_GROUP_ID), 200);
    EXPECT_EQ(MouseState->GetMouseCoordsX(GROUP_A), 300);
    EXPECT_EQ(MouseState->GetMouseCoordsY(GROUP_A), 400);
    EXPECT_EQ(MouseState->GetMouseCoordsX(GROUP_B), 500);
    EXPECT_EQ(MouseState->GetMouseCoordsY(GROUP_B), 600);

    MouseState->SetMouseCoords(GROUP_A, 999, 888);
    EXPECT_EQ(MouseState->GetMouseCoordsX(DEFAULT_GROUP_ID), 100);
    EXPECT_EQ(MouseState->GetMouseCoordsX(GROUP_B), 500);
}

HWTEST_F(MouseDeviceStateGroupTest, ButtonStatePerGroup_001, TestSize.Level1)
{
    MouseState->MouseBtnStateCounts(GROUP_A, BTN_LEFT_CODE, BUTTON_STATE_PRESSED);
    EXPECT_TRUE(MouseState->IsLeftBtnPressed(GROUP_A));
    EXPECT_FALSE(MouseState->IsLeftBtnPressed(GROUP_B));
    EXPECT_FALSE(MouseState->IsLeftBtnPressed(DEFAULT_GROUP_ID));

    MouseState->MouseBtnStateCounts(GROUP_A, BTN_LEFT_CODE, BUTTON_STATE_RELEASED);
    EXPECT_FALSE(MouseState->IsLeftBtnPressed(GROUP_A));
}

HWTEST_F(MouseDeviceStateGroupTest, GetPressedButtonsPerGroup_001, TestSize.Level1)
{
    MouseState->MouseBtnStateCounts(GROUP_A, BTN_LEFT_CODE, BUTTON_STATE_PRESSED);

    std::vector<int32_t> pressedA;
    MouseState->GetPressedButtons(GROUP_A, pressedA);
    EXPECT_FALSE(pressedA.empty());

    std::vector<int32_t> pressedB;
    MouseState->GetPressedButtons(GROUP_B, pressedB);
    EXPECT_TRUE(pressedB.empty());
}

HWTEST_F(MouseDeviceStateGroupTest, RemoveGroupState_001, TestSize.Level1)
{
    MouseState->SetMouseCoords(GROUP_A, 300, 400);
    EXPECT_EQ(MouseState->GetMouseCoordsX(GROUP_A), 300);

    MouseState->RemoveGroupState(GROUP_A);
    EXPECT_EQ(MouseState->GetMouseCoordsX(GROUP_A), 0);
}

HWTEST_F(MouseDeviceStateGroupTest, GetActiveGroupIds_001, TestSize.Level1)
{
    MouseState->SetMouseCoords(GROUP_A, 1, 1);
    MouseState->SetMouseCoords(GROUP_B, 2, 2);

    auto ids = MouseState->GetActiveGroupIds();
    EXPECT_GE(ids.size(), 2u);

    bool foundA = false;
    bool foundB = false;
    for (auto id : ids) {
        if (id == GROUP_A) foundA = true;
        if (id == GROUP_B) foundB = true;
    }
    EXPECT_TRUE(foundA);
    EXPECT_TRUE(foundB);
}

HWTEST_F(MouseDeviceStateGroupTest, RemoveDefaultGroupIsNoOp_001, TestSize.Level1)
{
    MouseState->SetMouseCoords(DEFAULT_GROUP_ID, 50, 60);
    MouseState->RemoveGroupState(DEFAULT_GROUP_ID);
    EXPECT_EQ(MouseState->GetMouseCoordsX(DEFAULT_GROUP_ID), 50);
}
} // namespace MMI
} // namespace OHOS
