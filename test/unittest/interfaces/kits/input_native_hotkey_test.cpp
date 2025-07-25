/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "input_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "nativetoken_kit.h"
#include "oh_input_manager.h"
#include "oh_key_code.h"
#include "token_setproc.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputNativeHotkeyTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

AccessTokenID tokenID_ = 0;
PermissionDef g_infoManagerTestPermDef = {
    .permissionName = "ohos.permission.ACTIVITY_MOTION",
    .bundleName = "InputNativeHotkeyTest",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "test InputNativeHotkeyTest",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};
PermissionStateFull g_infoManagerTestState = {
    .grantFlags = { 1 },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.ACTIVITY_MOTION",
    .resDeviceID = { "localTest" }
};
HapPolicyParams g_infoManagerTestPolicyParams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = { g_infoManagerTestPermDef },
    .permStateList = { g_infoManagerTestState },
};

HapInfoParams g_infoManagerTestInfoParams = {
    .bundleName = "InputNativeHotkeyTest",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "InputNativeHotkeyTest"
};
} // namespace

class InputNativeHotkeyTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        AccessTokenIDEx tokenIdEx = {0};
        tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParams, g_infoManagerTestPolicyParams);
        tokenID_ = tokenIdEx.tokenIdExStruct.tokenID;
        GTEST_LOG_(INFO) << "tokenID:" << tokenID_;
        ASSERT_NE(0, tokenID_);
        ASSERT_EQ(0, SetSelfTokenID(tokenID_));
    }
    static void TearDownTestCase(void)
    {
        ASSERT_NE(0, tokenID_);
        int32_t ret = AccessTokenKit::DeleteToken(tokenID_);
        ASSERT_EQ(INPUT_SUCCESS, ret);
    }
    void SetUp() {}
    void TearDown() {}
};

static void Input_HotkeyCallback(struct Input_Hotkey *hotkey)
{
    printf("Input_HotkeyCallback success");
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_001
 * @tc.desc: Subscribe ctrl + z
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_Z);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SERVICE_EXCEPTION);
    ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_002
 * @tc.desc: Subscribe ctrl + alt + z
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[2] = { KEYCODE_CTRL_LEFT, KEYCODE_ALT_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 2);
    OH_Input_SetFinalKey(hotkey, KEYCODE_Z);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_003
 * @tc.desc: Subscribe shift + alt + z
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[2] = { KEYCODE_SHIFT_LEFT, KEYCODE_ALT_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 2);
    OH_Input_SetFinalKey(hotkey, KEYCODE_Z);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_004
 * @tc.desc: Subscribe alt + z
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_ALT_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_Z);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_005
 * @tc.desc: Subscribe shift + c
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_SHIFT_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_C);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_006
 * @tc.desc: Subscribe ctrl + 9
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_9);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_SetFinalKey(hotkey, KEYCODE_NUMPAD_9);
    OH_Input_SetRepeat(hotkey, true);
    ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_007
 * @tc.desc: Subscribe ctrl + ↑
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_DPAD_UP);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_008
 * @tc.desc: Subscribe ctrl + ←
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_DPAD_LEFT);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_009
 * @tc.desc: Subscribe ctrl + F1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_F1);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_010
 * @tc.desc: Subscribe ctrl + home
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_MOVE_HOME);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_011
 * @tc.desc: Subscribe ctrl + enter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_ENTER);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_012
 * @tc.desc: Subscribe ctrl + p
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_P);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SERVICE_EXCEPTION);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_013
 * @tc.desc: Subscribe ctrl + alt + d + c
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[3] = { KEYCODE_CTRL_LEFT, KEYCODE_ALT_LEFT, KEYCODE_D };
    OH_Input_SetPreKeys(hotkey, prekeys, 3);
    OH_Input_SetFinalKey(hotkey, KEYCODE_C);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_014
 * @tc.desc: Subscribe ctrl + alt + d + 9
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[3] = { KEYCODE_CTRL_LEFT, KEYCODE_ALT_LEFT, KEYCODE_D };
    OH_Input_SetPreKeys(hotkey, prekeys, 3);
    OH_Input_SetFinalKey(hotkey, KEYCODE_9);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_015
 * @tc.desc: Subscribe 9 + d
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_9 };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_D);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_016
 * @tc.desc: Subscribe f + d
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_F };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_D);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_017
 * @tc.desc: Subscribe ctrl + meta
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_META_LEFT);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_018
 * @tc.desc: Subscribe left ctrl + right ctrl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_CTRL_RIGHT);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_019
 * @tc.desc: Subscribe ctrl + Scroll Lock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_SCROLL_LOCK);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_020
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = OH_Input_AddHotkeyMonitor(nullptr, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_021
 * @tc.desc: Verify the InjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_021, TestSize.Level1)
{
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[2] = { KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT };
    OH_Input_SetPreKeys(hotkey, prekeys, 2);
    int32_t key = 0;
    int32_t key1 = 0;
    int32_t *pressedKeys[2] = { &key, &key1 };
    int32_t pressedKeyNum = 0;
    Input_Result result = OH_Input_GetPreKeys(hotkey, pressedKeys, &pressedKeyNum);
    EXPECT_EQ(result, INPUT_SUCCESS);
    int32_t press= *pressedKeys[0];
    int32_t press1= *pressedKeys[1];
    EXPECT_EQ(press, KEYCODE_ALT_LEFT);
    EXPECT_EQ(press1, KEYCODE_ALT_RIGHT);

    OH_Input_SetFinalKey(hotkey, KEYCODE_TAB);
    int32_t finalKeyCode = 0;
    result = OH_Input_GetFinalKey(hotkey, &finalKeyCode);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_EQ(finalKeyCode, KEYCODE_TAB);

    OH_Input_SetRepeat(hotkey, true);
    bool isRepeat = false;
    result = OH_Input_GetRepeat(hotkey, &isRepeat);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_EQ(isRepeat, true);

    OH_Input_SetRepeat(hotkey, false);
    result = OH_Input_GetRepeat(hotkey, &isRepeat);
    EXPECT_EQ(result, INPUT_SUCCESS);
    EXPECT_EQ(isRepeat, false);

    OH_Input_DestroyHotkey(&hotkey);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_022
 * @tc.desc: Subscribe ctrl + tab
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_022, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_CTRL_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_TAB);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}

/**
 * @tc.name: InputNativeHotkeyTest_AddHotkeyMonitor_023
 * @tc.desc: Subscribe alt + tab
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputNativeHotkeyTest, InputNativeHotkeyTest_AddHotkeyMonitor_023, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Input_Hotkey *hotkey = OH_Input_CreateHotkey();
    ASSERT_NE(hotkey, nullptr);

    int32_t prekeys[1] = { KEYCODE_ALT_LEFT };
    OH_Input_SetPreKeys(hotkey, prekeys, 1);
    OH_Input_SetFinalKey(hotkey, KEYCODE_TAB);
    OH_Input_SetRepeat(hotkey, false);
    int32_t ret = OH_Input_AddHotkeyMonitor(hotkey, Input_HotkeyCallback);
#ifndef OHOS_BUILD_PC_UNIT_TEST
    EXPECT_NE(ret, INPUT_OCCUPIED_BY_OTHER);
#endif // OHOS_BUILD_PC_UNIT_TEST
#ifdef OHOS_BUILD_PC_UNIT_TEST
    EXPECT_EQ(ret, INPUT_OCCUPIED_BY_OTHER);
#endif // OHOS_BUILD_PC_UNIT_TEST
    OH_Input_RemoveHotkeyMonitor(hotkey, Input_HotkeyCallback);
    OH_Input_DestroyHotkey(&hotkey);
    EXPECT_EQ(hotkey, nullptr);
}
} // namespace MMI
} // namespace OHOS
