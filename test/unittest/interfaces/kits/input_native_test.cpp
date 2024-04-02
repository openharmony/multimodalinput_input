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

#include "oh_input_manager.h"
#include "oh_key_code.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputNativeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: InputNativeTest_KeyState_001
 * @tc.desc: Verify the create and destroy of key states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyState_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    if (keyState == nullptr) {
        ASSERT_EQ(keyState, nullptr);
    } else {
        ASSERT_NE(keyState, nullptr);
        OH_Input_DestroyKeyState(&keyState);
    }
}

/**
 * @tc.name: InputNativeTest_KeyCode_001
 * @tc.desc: Verify the set and get of key states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyCode_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeyCode(keyState, 2000);
    int32_t keyCode = OH_Input_GetKeyCode(keyState);
    ASSERT_EQ(keyCode, 2000);
    OH_Input_DestroyKeyState(&keyState);
}

/**
 * @tc.name: InputNativeTest_KeyPressed_001
 * @tc.desc: Verify the set and get of key pressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeyPressed_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeyPressed(keyState, 0);
    int32_t keyAction = OH_Input_GetKeyPressed(keyState);
    ASSERT_EQ(keyAction, 0);
    OH_Input_DestroyKeyState(&keyState);
}

/**
 * @tc.name: InputNativeTest_KeySwitch_001
 * @tc.desc: Verify the set and get of key switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_KeySwitch_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeySwitch(keyState, 2);
    int32_t keySwitch = OH_Input_GetKeySwitch(keyState);
    ASSERT_EQ(keySwitch, 2);
    OH_Input_DestroyKeyState(&keyState);
}

/**
 * @tc.name: InputNativeTest_GetKeyState_001
 * @tc.desc: Verify the GetKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeTest, InputNativeTest_GetKeyState_001, TestSize.Level1)
{
    struct Input_KeyState* keyState = OH_Input_CreateKeyState();
    ASSERT_NE(keyState, nullptr);
    OH_Input_SetKeyCode(keyState, 22);
    OH_Input_GetKeyState(keyState);
    ASSERT_EQ(OH_Input_GetKeyPressed(keyState), KEY_RELEASED);
    ASSERT_EQ(OH_Input_GetKeySwitch(keyState), KEY_DEFAULT);
    ASSERT_EQ(OH_Input_GetKeyState(keyState), INPUT_SUCCESS);
    OH_Input_DestroyKeyState(&keyState);
}
} // namespace MMI
} // namespace OHOS
