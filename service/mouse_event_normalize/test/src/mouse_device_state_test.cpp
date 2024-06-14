/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class MouseDeviceStateTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MouseDeviceStateTest::SetUpTestCase(void)
{
}

void MouseDeviceStateTest::TearDownTestCase(void)
{
}

void MouseDeviceStateTest::SetUp()
{
}

void MouseDeviceStateTest::TearDown()
{
}

/**
 * @tc.name: MouseDeviceStateTest_GetMouseCoordsX_001
 * @tc.desc: Test GetMouseCoordsX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseDeviceStateTest, MouseDeviceStateTest_GetMouseCoordsX_001, TestSize.Level1)
{
    int32_t idNames = 0;
    ASSERT_EQ(MouseState->GetMouseCoordsX(), idNames);
}

/**
 * @tc.name: MouseDeviceStateTest_IsLeftBtnPressed_002
 * @tc.desc: Test IsLeftBtnPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseDeviceStateTest, MouseDeviceStateTest_IsLeftBtnPressed_002, TestSize.Level1)
{
    int32_t x = 0;
    int32_t y = 0;
    MouseState->SetMouseCoords(x, y);
    bool isPress = false;
    ASSERT_EQ(MouseState->IsLeftBtnPressed(), isPress);
    MouseState->MouseBtnStateCounts(MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE, BUTTON_STATE_PRESSED);
    isPress = true;
    ASSERT_EQ(MouseState->IsLeftBtnPressed(), isPress);
}

/**
 * @tc.name: MouseDeviceStateTest_GetPressedButtons_003
 * @tc.desc: Test GetPressedButtons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseDeviceStateTest, MouseDeviceStateTest_GetPressedButtons_003, TestSize.Level1)
{
    MouseState->MouseBtnStateCounts(MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE, BUTTON_STATE_PRESSED);
    std::vector<int32_t> pressedButtons;
    MouseState->GetPressedButtons(pressedButtons);
    std::vector<int32_t> idNames = {PointerEvent::MOUSE_BUTTON_LEFT};
    ASSERT_EQ(pressedButtons, idNames);
}

/**
 * @tc.name: MouseDeviceStateTest_LibinputChangeToPointer_004
 * @tc.desc: Test LibinputChangeToPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseDeviceStateTest, MouseDeviceStateTest_LibinputChangeToPointer_004, TestSize.Level1)
{
    const uint32_t keyValue = MouseDeviceState::LIBINPUT_LEFT_BUTTON_CODE;
    int32_t idNames = PointerEvent::MOUSE_BUTTON_LEFT;
    ASSERT_EQ(MouseState->LibinputChangeToPointer(keyValue), idNames);
}

/**
 * @tc.name: MouseDeviceStateTest_ChangeMouseState
 * @tc.desc: Test ChangeMouseState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseDeviceStateTest, MouseDeviceStateTest_ChangeMouseState, TestSize.Level1)
{
    int32_t btnStateCount = 1;
    MouseState->ChangeMouseState(BUTTON_STATE_PRESSED, btnStateCount);
    EXPECT_EQ(btnStateCount, 2);
    btnStateCount = 2;
    MouseState->ChangeMouseState(BUTTON_STATE_RELEASED, btnStateCount);
    EXPECT_EQ(btnStateCount, 1);
    btnStateCount = 10;
    MouseState->ChangeMouseState(BUTTON_STATE_PRESSED, btnStateCount);
    EXPECT_EQ(btnStateCount, 8);
    btnStateCount = -1;
    MouseState->ChangeMouseState(BUTTON_STATE_RELEASED, btnStateCount);
    EXPECT_EQ(btnStateCount, 0);
}
}
}