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

#include "key_command_handler_util.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandlerUtilTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class KeyCommandHandlerUtilTest : public testing::Test {
public:
static void SetUpTestCase(void) {}
static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSpecialType_001
 * @tc.desc: Test the function IsSpecialType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSpecialType_001, TestSize.Level1)
{
CALL_TEST_DEBUG;
SpecialType type = SPECIAL_ALL;
int32_t keyCode = 1;
bool result = OHOS::MMI::IsSpecialType(keyCode, type);
EXPECT_FALSE(result);
type = SUBSCRIBER_BEFORE_DELAY;
keyCode = 2;
result = OHOS::MMI::IsSpecialType(keyCode, type);
EXPECT_FALSE(result);
type = KEY_DOWN_ACTION;
keyCode = 3;
result = OHOS::MMI::IsSpecialType(keyCode, type);
EXPECT_FALSE(result);
type = KEY_DOWN_ACTION;
keyCode = -1;
result = OHOS::MMI::IsSpecialType(keyCode, type);
EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetBusinessId_001
 * @tc.desc: Test the function GetBusinessId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetBusinessId_001, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON *jsonData = cJSON_CreateString("not an object");
std::string businessIdValue;
std::vector<std::string> businessIds;
bool result = OHOS::MMI::GetBusinessId(jsonData, businessIdValue, businessIds);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetBusinessId_002
 * @tc.desc: Test the function GetBusinessId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetBusinessId_002, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON *jsonData = cJSON_CreateObject();
cJSON_AddItemToObject(jsonData, "businessId", cJSON_CreateNumber(123));
std::string businessIdValue;
std::vector<std::string> businessIds;
bool result = OHOS::MMI::GetBusinessId(jsonData, businessIdValue, businessIds);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_001
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_001, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON* jsonData = cJSON_CreateObject();
ShortcutKey shortcutKey;
bool result = OHOS::MMI::GetPreKeys(jsonData, shortcutKey);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_002
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_002, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON* jsonData = cJSON_CreateObject();
cJSON* preKey = cJSON_CreateArray();
for (int i = 0; i < MAX_PREKEYS_NUM + 1; ++i) {
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
}
cJSON_AddItemToObject(jsonData, "preKey", preKey);
ShortcutKey shortcutKey;
bool result = OHOS::MMI::GetPreKeys(jsonData, shortcutKey);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_003
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_003, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON* jsonData = cJSON_CreateObject();
cJSON_AddItemToObject(jsonData, "preKey", cJSON_CreateString("invalid"));
ShortcutKey shortcutKey;
bool result = OHOS::MMI::GetPreKeys(jsonData, shortcutKey);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_004
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_004, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON* jsonData = cJSON_CreateObject();
cJSON* preKey = cJSON_CreateArray();
cJSON_AddItemToArray(preKey, cJSON_CreateNumber(-1));
cJSON_AddItemToObject(jsonData, "preKey", preKey);
ShortcutKey shortcutKey;
bool result = OHOS::MMI::GetPreKeys(jsonData, shortcutKey);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_005
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_005, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON* jsonData = cJSON_CreateObject();
cJSON* preKey = cJSON_CreateArray();
cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
cJSON_AddItemToObject(jsonData, "preKey", preKey);
ShortcutKey shortcutKey;
bool result = OHOS::MMI::GetPreKeys(jsonData, shortcutKey);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSpecialType_002
 * @tc.desc: Test keyCode is not in SPECIAL_KEYS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSpecialType_002, TestSize.Level1)
{
CALL_TEST_DEBUG;
int32_t keyCode = 999;
SpecialType type = SpecialType::SPECIAL_ALL;
EXPECT_FALSE(OHOS::MMI::IsSpecialType(keyCode, type));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSpecialType_003
 * @tc.desc: The corresponding value is not equal to SpecialType.: SPECIAL_ALL and input type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSpecialType_003, TestSize.Level1)
{
CALL_TEST_DEBUG;
int32_t keyCode = 16;
SpecialType type = SpecialType::SPECIAL_ALL;
EXPECT_FALSE(OHOS::MMI::IsSpecialType(keyCode, type));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSpecialType_004
 * @tc.desc: The test keyCode is in SPECIAL_KEYS and the value is equal to SpecialType.: SPECIAL_ALL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSpecialType_004, TestSize.Level1)
{
CALL_TEST_DEBUG;
int32_t keyCode = 0;
SpecialType type = SpecialType::SPECIAL_ALL;
EXPECT_FALSE(OHOS::MMI::IsSpecialType(keyCode, type));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetBusinessId_003
 * @tc.desc: Test the scenario where the JSON object is not a valid object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetBusinessId_003, TestSize.Level1)
{
CALL_TEST_DEBUG;
cJSON *jsonData = nullptr;
std::string businessIdValue;
std::vector<std::string> businessIds;
bool result = OHOS::MMI::GetBusinessId(jsonData, businessIdValue, businessIds);
EXPECT_FALSE(result);
cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetBusinessId_004
 * @tc.desc: Test the scenario where businessId is not a string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetBusinessId_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    std::vector<std::string> businessIds;
    cJSON_AddItemToObject(jsonData, "businessIds", cJSON_CreateNumber(123));
    std::string businessIdValue;
    bool result = OHOS::MMI::GetBusinessId(jsonData, businessIdValue, businessIds);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetBusinessId_005
 * @tc.desc: Test the normal running condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetBusinessId_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    std::vector<std::string> businessIds;
    cJSON_AddStringToObject(jsonData, "businessId", "testBusinessId");
    std::string businessIdValue;
    bool result = OHOS::MMI::GetBusinessId(jsonData, businessIdValue, businessIds);
    EXPECT_TRUE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_006
 * @tc.desc: Test the case that the input jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    ShortcutKey shortcutKey;
    EXPECT_FALSE(OHOS::MMI::GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_007
 * @tc.desc: Test the case that preKey is not an array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "preKey", cJSON_CreateString("test"));
    ShortcutKey shortcutKey;
    EXPECT_FALSE(OHOS::MMI::GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_008
 * @tc.desc: Test the case that the size of preKey exceeds MAX_PREKEYS_NUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    for (int i = 0; i < 10; ++i) {
        cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
    }
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(OHOS::MMI::GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_009
 * @tc.desc: Test if the element in preKey is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateString("not a number"));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(OHOS::MMI::GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_010
 * @tc.desc: Tests if the number in preKey is less than 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(-1));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(OHOS::MMI::GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_011
 * @tc.desc: Test the duplicated number in preKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(OHOS::MMI::GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetPreKeys_012
 * @tc.desc: Test the normal running condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetPreKeys_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(3));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(4));
    ShortcutKey shortcutKey;
    EXPECT_TRUE(OHOS::MMI::GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
 /**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey001
 * @tc.number: KeyCommandHandlerTest_CheckSpecialRepeatKey_001
 * @tc.desc: Verify that when the key code configured for a repeat key does not match the actual key code
 * of the key event, the special repeat key check should return false.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey001, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = 1;
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(0);

    KeyCommandHandler handler;
    EXPECT_FALSE(handler.CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey002
 * @tc.number: KeyCommandHandlerTest_CheckSpecialRepeatKey_002
 * @tc.desc: Test the key event for the non-volume down button;
 * it should return false even if the key code matches.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey002, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = 1;
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(1);

    KeyCommandHandler handler;
    EXPECT_FALSE(handler.CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey003
 * @tc.number: KeyCommandHandlerTest_CheckSpecialRepeatKey_003
 * @tc.desc: Verify that when the application bundleName does not contain ".camera",
 * the special repeat key check for the volume down button should return false.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey003, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.app";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    KeyCommandHandler handler;
    EXPECT_FALSE(handler.CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey004
 * @tc.number: KeyCommandHandlerTest_CheckSpecialRepeatKey_004
 * @tc.desc: When the camera app is in the foreground and the screen is locked,
 * the special repeat key check for the volume down button should return true.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey004, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera.camera";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    EXPECT_CALL(*winMgr, JudgeCaramaInFore()).WillOnce(Return(true));
    EXPECT_CALL(*displayMonitor, GetScreenStatus()).WillOnce(Return("ON"));
    EXPECT_CALL(*displayMonitor, GetScreenLocked()).WillOnce(Return(true));

    KeyCommandHandler handler;
    EXPECT_TRUE(handler.CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey005
 * @tc.number: KeyCommandHandlerTest_CheckSpecialRepeatKey_005
 * @tc.desc: Verify that when the call state is active,
 * the special repeat key check for the volume down button should return true.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey005, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera.camera";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    EXPECT_CALL(*deviceMonitor, GetCallState()).WillOnce(Return(StateType::CALL_STATUS_ACTIVE));

    KeyCommandHandler handler;
    EXPECT_TRUE(handler.CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey006
 * @tc.number: KeyCommandHandlerTest_CheckSpecialRepeatKey_006
 * @tc.desc: When testing screen lock with no music activated,
 * the special repeat key check for the volume down button should return false.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey006, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera.camera";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    EXPECT_CALL(*displayMonitor, GetScreenLocked()).WillOnce(Return(true));
    EXPECT_CALL(*deviceMonitor, IsMusicActivate()).WillOnce(Return(false));

    KeyCommandHandler handler;
    EXPECT_FALSE(handler.CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey007
 * @tc.number: KeyCommandHandlerTest_CheckSpecialRepeatKey_007
 * @tc.desc: Verify that when music is active and the screen is not locked,
 * the special repeat key check for the volume down button should return true.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey007, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera.camera";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    EXPECT_CALL(*displayMonitor, GetScreenStatus()).WillOnce(Return("ON"));
    EXPECT_CALL(*displayMonitor, GetScreenLocked()).WillOnce(Return(false));
    EXPECT_CALL(*deviceMonitor, IsMusicActivate()).WillOnce(Return(true));

    KeyCommandHandler handler;
    EXPECT_TRUE(handler.CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility001
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_001
 * @tc.desc: Test the ability to initiate repeated key presses,
 * verifying the correct process for handling key events and initiating functionality.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility001, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyCommandHandler handler;
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillOnce(Return(subscriberHandlerMock_));
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .Times(1);
    EXPECT_CALL(handler, LaunchAbility(_))
        .Times(1);
    EXPECT_CALL(handler, UnregisterMistouchPrevention())
        .Times(1);

    handler.LaunchRepeatKeyAbility(item, keyEvent);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount001
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_001
 * @tc.desc: To verify that false is returned when a null key event is transferred.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount001, TestSize.Level1)
{
    RepeatKey item;
    EXPECT_FALSE(handler_->HandleRepeatKeyCount(item, nullptr));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount002
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_002
 * @tc.desc: When the key code configured for the repeat key does not match
 * the actual key event key code, the UP event handler should return false.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount002, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    EXPECT_FALSE(handler_->HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount003
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_003
 * @tc.desc: Verify the time interval calculation logic and timer settings for the POWER key UP event.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount003, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(200);
    
    handler_->downActionTime_ = 100;
    
    EXPECT_CALL(mockTimerMgr_, AddTimer(900, 1, _, "KeyCommandHandler-HandleRepeatKeyCount"))
        .WillOnce(Return(VALID_TIMER_ID));
    
    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler_->upActionTime_, 200);
    EXPECT_EQ(handler_->repeatKey_.keyCode, KeyEvent::KEYCODE_POWER);
    EXPECT_EQ(handler_->repeatKey_.keyAction, KeyEvent::KEY_ACTION_UP);
    EXPECT_EQ(handler_->repeatTimerId_, VALID_TIMER_ID);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount004
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_004
 * @tc.desc: When there is a wallet delay,
 * the POWER key UP event should use the wallet delay time to set the timer.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount004, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    handler_->walletLaunchDelayTimes_ = 500;
    
    EXPECT_CALL(mockTimerMgr_, AddTimer(500, 1, _, _))
        .WillOnce(Return(VALID_TIMER_ID));
    
    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount005
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_005
 * @tc.desc: To verify that false is returned when the timer fails to be added.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount005, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    EXPECT_CALL(mockTimerMgr_, AddTimer(_, 1, _, _))
        .WillOnce(Return(INVALID_TIMER_ID));
    
    EXPECT_FALSE(handler_->HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount006
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_006
 * @tc.desc: The DOWN event for the new button should correctly initialize the count and status.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount006, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(100);
    
    handler_->repeatKey_.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    
    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler_->count_, 1);
    EXPECT_EQ(handler_->repeatKey_.keyCode, KeyEvent::KEYCODE_VOLUME_UP);
    EXPECT_EQ(handler_->repeatKey_.keyAction, KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(handler_->isDownStart_);
    EXPECT_EQ(handler_->downActionTime_, 100);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount007
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_007
 * @tc.desc: Verify that the count and state mapping should be reset when a repeated DOWN event occurs.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount007, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    handler_->repeatKey_.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    handler_->repeatKey_.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->count_ = 5;
    handler_->isDownStart_ = true;
    handler_->repeatKeyCountMap_[KeyEvent::KEYCODE_VOLUME_UP] = 3;
    
    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler_->count_, 0);
    EXPECT_FALSE(handler_->isDownStart_);
    EXPECT_TRUE(handler_->repeatKeyCountMap_.empty());
}
/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount008
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_008
 * @tc.desc: The complete key sequence should correctly update the count and action status.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount008, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    
    auto upEvent = KeyEvent::Create();
    upEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    upEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    upEvent->SetActionTime(UP_ACTION_TIME);

    EXPECT_CALL(mockTimerMgr_, AddTimer(_, 1, _, _))
        .WillOnce(Return(VALID_TIMER_ID));

    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, upEvent));

    auto downEvent = KeyEvent::Create();
    downEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    downEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    downEvent->SetActionTime(150);

    handler_->repeatKey_.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    handler_->repeatKey_.keyAction = KeyEvent::KEY_ACTION_UP;
    handler_->count_ = 1;
    
    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, downEvent));
    EXPECT_EQ(handler_->count_, 2);
    EXPECT_EQ(handler_->repeatKey_.keyAction, KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(handler_->isDownStart_);
    EXPECT_EQ(handler_->downActionTime_, 150);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount009
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_009
 * @tc.desc: Verify that when the key press interval is less than the set value,
 * the existing timer should be canceled and the state reset.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount009, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    
    handler_->repeatTimerId_ = VALID_TIMER_ID;
    
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(150);
    
    handler_->upActionTime_ = UP_ACTION_TIME;
    handler_->intervalTime_ = UP_ACTION_TIME;

    EXPECT_CALL(mockTimerMgr_, RemoveTimer(VALID_TIMER_ID));
    
    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler_->repeatTimerId_, -1);
    EXPECT_FALSE(handler_->isHandleSequence_);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount010
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_010
 * @tc.desc: To test the UP event of the non-POWER key,
 * set the timer using the default interval time.
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount010, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    EXPECT_CALL(mockTimerMgr_, AddTimer(handler_->intervalTime_, 1, _, _))
        .WillOnce(Return(VALID_TIMER_ID));
    
    EXPECT_TRUE(handler_->HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility001
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_001
 * @tc.desc: Verify VOLUME_DOWN with camera app when ret_ is not LIGHT_STAY_AWAY
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility001, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.camera";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyCommandHandler handler;
    handler.ret_.store(0);  // Not LIGHT_STAY_AWAY

    EXPECT_CALL(handler, LaunchAbility(_)).Times(1);
    EXPECT_CALL(handler, UnregisterMistouchPrevention()).Times(1);
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillOnce(Return(subscriberHandlerMock_));
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .WillOnce([keyEvent](std::shared_ptr<KeyEvent> event) {
            EXPECT_EQ(event->GetKeyAction(), KeyEvent::KEY_ACTION_CANCEL);
            EXPECT_EQ(event->GetKeyCode(), keyEvent->GetKeyCode());
        });
    
    handler.LaunchRepeatKeyAbility(item, keyEvent);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility002
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_002
 * @tc.desc: Verify VOLUME_DOWN with camera app when ret_ is LIGHT_STAY_AWAY
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility002, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.camera";
    auto keyEvent = std::make_shared<KeyEvent>();

    KeyCommandHandler handler;
    handler.ret_.store(LIGHT_STAY_AWAY);

    EXPECT_CALL(handler, LaunchAbility(_)).Times(0);
    EXPECT_CALL(handler, UnregisterMistouchPrevention()).Times(1);
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillOnce(Return(subscriberHandlerMock_));
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_));
    
    handler.LaunchRepeatKeyAbility(item, keyEvent);
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility003
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_003
 * @tc.desc: Verify non-VOLUME_DOWN key with camera app
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility003, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;  // Non-volume down
    item.ability.bundleName = "com.ohos.camera";
    auto keyEvent = std::make_shared<KeyEvent>();

    KeyCommandHandler handler;
    handler.ret_.store(0);

    EXPECT_CALL(handler, LaunchAbility(_)).Times(1);
    EXPECT_CALL(handler, UnregisterMistouchPrevention()).Times(0); // Not called for non-volume
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillOnce(Return(subscriberHandlerMock_));
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_));
    
    handler.LaunchRepeatKeyAbility(item, keyEvent);
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility004
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_004
 * @tc.desc: Verify VOLUME_DOWN with non-camera app
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility004, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.music";  // Non-camera
    auto keyEvent = std::make_shared<KeyEvent>();

    KeyCommandHandler handler;
    handler.ret_.store(0);

    EXPECT_CALL(handler, LaunchAbility(_)).Times(1);
    EXPECT_CALL(handler, UnregisterMistouchPrevention()).Times(0);
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillOnce(Return(subscriberHandlerMock_));
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_));
    
    handler.LaunchRepeatKeyAbility(item, keyEvent);
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility005
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_005
 * @tc.desc: Verify cancel event propagation
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility005, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    item.ability.bundleName = "com.ohos.settings";
    auto keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyCommandHandler handler;
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .WillOnce([](std::shared_ptr<KeyEvent> event) {
            EXPECT_EQ(KeyEvent::KEY_ACTION_CANCEL, event->GetKeyAction());
            EXPECT_EQ(KeyEvent::KEYCODE_POWER, event->GetKeyCode());
        });
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillOnce(Return(subscriberHandlerMock_));
    
    handler.LaunchRepeatKeyAbility(item, keyEvent);
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility006
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_006
 * @tc.desc: Verify map clearing
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility006, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    item.ability.bundleName = "com.ohos.music";
    auto keyEvent = std::make_shared<KeyEvent>();

    KeyCommandHandler handler;
    handler.repeatKeyCountMap_[KeyEvent::KEYCODE_VOLUME_UP] = 3;
    
    handler.LaunchRepeatKeyAbility(item, keyEvent);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey001
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_001
 * @tc.desc: Verify that non-SOS page names disable power key freezing
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey001, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.isFreezePowerKey_ = true;  // Initial state
    
    EXPECT_EQ(handler.SetIsFreezePowerKey("HomePage"), RET_OK);
    EXPECT_FALSE(handler.isFreezePowerKey_);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey002
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_002
 * @tc.desc: Verify SOS page name resets state and starts timer
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey002, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 5;
    handler.launchAbilityCount_ = 2;
    handler.repeatKeyCountMap_ = {{1, 1}};
    handler.sosDelayTimerId_ = 100;  // Existing timer
    
    // Setup timer expectations
    EXPECT_CALL(*timerMgrMock_, RemoveTimer(100)).Times(1);
    EXPECT_CALL(*timerMgrMock_, AddTimer(SOS_COUNT_DOWN_TIMES/1000, 1, _, "KeyCommandHandler-SetIsFreezePowerKey"))
        .WillOnce(Return(200));  // New timer ID
    
    EXPECT_EQ(handler.SetIsFreezePowerKey("SosCountdown"), RET_OK);
    EXPECT_TRUE(handler.isFreezePowerKey_);
    EXPECT_EQ(handler.count_, 0);
    EXPECT_EQ(handler.launchAbilityCount_, 0);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
    EXPECT_GT(handler.sosLaunchTime_, 0);
    EXPECT_EQ(handler.sosDelayTimerId_, 200);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey003
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_003
 * @tc.desc: Verify timer failure handling
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey003, TestSize.Level1)
{
    KeyCommandHandler handler;
    
    EXPECT_CALL(*timerMgrMock_, AddTimer(_, _, _, _))
        .WillOnce(Return(-1));  // Timer failure
    
    EXPECT_EQ(handler.SetIsFreezePowerKey("SosCountdown"), RET_ERR);
    EXPECT_FALSE(handler.isFreezePowerKey_);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey004
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_004
 * @tc.desc: Verify no timer removal when no existing timer
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey004, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.sosDelayTimerId_ = -1;  // No existing timer
    
    EXPECT_CALL(*timerMgrMock_, RemoveTimer(_)).Times(0);  // No removal
    EXPECT_CALL(*timerMgrMock_, AddTimer(_, _, _, _))
        .WillOnce(Return(300));
    
    EXPECT_EQ(handler.SetIsFreezePowerKey("SosCountdown"), RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey005
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_005
 * @tc.desc: Verify timer callback resets freeze state
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey005, TestSize.Level1)
{
    KeyCommandHandler handler;
    TimerCallback callback;
    
    // Capture timer callback
    EXPECT_CALL(*timerMgrMock_, AddTimer(_, _, _, _))
        .WillOnce(DoAll(SaveArg<2>(&callback), Return(400)));
    
    handler.SetIsFreezePowerKey("SosCountdown");
    ASSERT_TRUE(callback);
    
    // Execute timer callback
    callback();
    EXPECT_FALSE(handler.isFreezePowerKey_);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey006
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_006
 * @tc.desc: Verify mutex lock during execution
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey006, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.mutex_.lock();  // Lock mutex to test contention
    
    std::thread testThread([&] {
        EXPECT_EQ(handler.SetIsFreezePowerKey("SosCountdown"), RET_OK);
    });
    
    // Verify thread blocks on mutex
    auto status = testThread.join_for(std::chrono::milliseconds(100));
    EXPECT_NE(status, std::future_status::ready);
    
    handler.mutex_.unlock();  // Release lock
    testThread.join();
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount001
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_001
 * @tc.desc: Verify UP event for non-POWER key sets timer with default interval
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount001, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(100);
    
    KeyCommandHandler handler;
    handler.intervalTime_ = 500;
    
    EXPECT_CALL(*timerMgrMock_, AddTimer(500, 1, _, "KeyCommandHandler-HandleRepeatKeyCount"))
        .WillOnce(Return(100));
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler.upActionTime_, 100);
    EXPECT_EQ(handler.repeatKey_.keyCode, KeyEvent::KEYCODE_VOLUME_UP);
    EXPECT_EQ(handler.repeatKey_.keyAction, KeyEvent::KEY_ACTION_UP);
    EXPECT_EQ(handler.repeatTimerId_, 100);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount002
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_002
 * @tc.desc: Verify POWER UP event calculates interval from key press duration
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount002, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(300);
    
    KeyCommandHandler handler;
    handler.intervalTime_ = 1000;
    handler.downActionTime_ = 100;  // Press duration = 200ms
    
    EXPECT_CALL(*timerMgrMock_, AddTimer(800, 1, _, _))  // 1000 - 200 = 800
        .WillOnce(Return(101));
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount003
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_003
 * @tc.desc: Verify wallet delay overrides POWER key interval calculation
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount003, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    KeyCommandHandler handler;
    handler.walletLaunchDelayTimes_ = 300;
    
    EXPECT_CALL(*timerMgrMock_, AddTimer(300, 1, _, _))
        .WillOnce(Return(102));
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount004
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_004
 * @tc.desc: Verify timer failure returns false for UP event
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount004, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    EXPECT_CALL(*timerMgrMock_, AddTimer(_, _, _, _))
        .WillOnce(Return(-1));
    
    KeyCommandHandler handler;
    EXPECT_FALSE(handler.HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount005
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_005
 * @tc.desc: Verify new key DOWN initializes state
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount005, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(200);
    
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_VOLUME_UP; // Different key
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler.count_, 1);
    EXPECT_EQ(handler.repeatKey_.keyCode, KeyEvent::KEYCODE_VOLUME_DOWN);
    EXPECT_EQ(handler.repeatKey_.keyAction, KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(handler.isDownStart_);
    EXPECT_EQ(handler.downActionTime_, 200);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount006
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_006
 * @tc.desc: Verify repeated DOWN resets state
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount006, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    handler.repeatKey_.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.count_ = 3;
    handler.isDownStart_ = true;
    handler.repeatKeyCountMap_[KeyEvent::KEYCODE_VOLUME_UP] = 2;
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler.count_, 0);
    EXPECT_FALSE(handler.isDownStart_);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount007
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_007
 * @tc.desc: Verify DOWN after UP increments count
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount007, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    auto downEvent = KeyEvent::Create();
    downEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    downEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    downEvent->SetActionTime(150);
    
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_POWER;
    handler.repeatKey_.keyAction = KeyEvent::KEY_ACTION_UP; // Previous was UP
    handler.count_ = 1;
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, downEvent));
    EXPECT_EQ(handler.count_, 2);
    EXPECT_EQ(handler.repeatKey_.keyAction, KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(handler.isDownStart_);
    EXPECT_EQ(handler.downActionTime_, 150);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount008
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_008
 * @tc.desc: Verify early DOWN cancels existing timer
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount008, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(150);
    
    KeyCommandHandler handler;
    handler.upActionTime_ = 100;
    handler.intervalTime_ = 500; // Time since up: 50ms < interval
    handler.repeatTimerId_ = 200;
    
    EXPECT_CALL(*timerMgrMock_, RemoveTimer(200)).Times(1);
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, keyEvent));
    EXPECT_EQ(handler.repeatTimerId_, -1);
    EXPECT_FALSE(handler.isHandleSequence_);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount009
 * @tc.number: KeyCommandHandlerTest_HandleRepeatKeyCount_009
 * @tc.desc: Verify late DOWN doesn't cancel timer
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount009, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(700);
    
    KeyCommandHandler handler;
    handler.upActionTime_ = 100;
    handler.intervalTime_ = 500; // Time since up: 600ms > interval
    handler.repeatTimerId_ = 201;
    
    EXPECT_CALL(*timerMgrMock_, RemoveTimer(_)).Times(0);
    
    EXPECT_TRUE(handler.HandleRepeatKeyCount(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent001
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_001
 * @tc.desc: Verify no action when isHandleSequence_ is true
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent001, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.isHandleSequence_ = true;
    handler.count_ = 5;
    handler.launchAbilityCount_ = 2;
    
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler()).Times(0);
    
    handler.SendKeyEvent();
    EXPECT_EQ(handler.count_, 0);
    EXPECT_EQ(handler.launchAbilityCount_, 0);
    EXPECT_FALSE(handler.isDownStart_);
    EXPECT_FALSE(handler.isHandleSequence_);
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent002
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_002
 * @tc.desc: Verify special key handling with KEY_DOWN_ACTION
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent002, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_BACK;
    handler.count_ = 3;
    handler.launchAbilityCount_ = 1;
    handler.repeatKeyMaxTimes_[KeyEvent::KEYCODE_BACK] = 5;
    
    EXPECT_CALL(handler, IsSpecialType(KeyEvent::KEYCODE_BACK, SpecialType::KEY_DOWN_ACTION))
        .WillOnce(Return(true));
    EXPECT_CALL(handler, HandleSpecialKeys(KeyEvent::KEYCODE_BACK, KeyEvent::KEY_ACTION_UP))
        .Times(2);
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .Times(4);
    
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillRepeatedly(Return(subscriberHandlerMock_));
    
    handler.SendKeyEvent();
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent003
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_003
 * @tc.desc: Verify POWER key cancel event at max count
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent003, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_POWER;
    handler.count_ = 5;
    handler.launchAbilityCount_ = 4;
    handler.repeatKeyMaxTimes_[KeyEvent::KEYCODE_POWER] = 5;
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .WillOnce([](std::shared_ptr<KeyEvent> event) {
            EXPECT_EQ(event->GetKeyCode(), KeyEvent::KEYCODE_POWER);
            EXPECT_EQ(event->GetKeyAction(), KeyEvent::KEY_ACTION_CANCEL);
        });
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_)).Times(1);
    
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillRepeatedly(Return(subscriberHandlerMock_));
    
    handler.SendKeyEvent();
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent004
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_004
 * @tc.desc: Verify DOWN event skipping on first iteration
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent004, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    handler.count_ = 3;
    handler.launchAbilityCount_ = 0;
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .Times(0);
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .WillOnce([](std::shared_ptr<KeyEvent> event) {
            EXPECT_EQ(event->GetKeyAction(), KeyEvent::KEY_ACTION_UP);
        });
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .Times(2);
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .Times(2);
    
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillRepeatedly(Return(subscriberHandlerMock_));
    
    handler.SendKeyEvent();
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent005
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_005
 * @tc.desc: Verify state reset after execution
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent005, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 2;
    handler.launchAbilityCount_ = 1;
    handler.isDownStart_ = true;
    handler.isHandleSequence_ = false;
    handler.repeatKeyCountMap_[KeyEvent::KEYCODE_VOLUME_UP] = 3;
    
    handler.SendKeyEvent();
    
    EXPECT_EQ(handler.count_, 0);
    EXPECT_EQ(handler.launchAbilityCount_, 0);
    EXPECT_FALSE(handler.isDownStart_);
    EXPECT_FALSE(handler.isHandleSequence_);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent006
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_006
 * @tc.desc: Verify no events when count <= launchAbilityCount
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent006, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 2;
    handler.launchAbilityCount_ = 3;
    
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler()).Times(0);
    
    handler.SendKeyEvent();
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent007
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_007
 * @tc.desc: Verify normal DOWN/UP sequence for non-special keys
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent007, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_ENTER;
    handler.count_ = 2;
    handler.launchAbilityCount_ = 0;
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .WillOnce([](auto event) { EXPECT_EQ(KeyEvent::KEY_ACTION_UP, event->GetKeyAction()); });
    
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .WillOnce([](auto event) { EXPECT_EQ(KeyEvent::KEY_ACTION_DOWN, event->GetKeyAction()); });
    EXPECT_CALL(*subscriberHandlerMock_, HandleKeyEvent(_))
        .WillOnce([](auto event) { EXPECT_EQ(KeyEvent::KEY_ACTION_UP, event->GetKeyAction()); });
    
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillRepeatedly(Return(subscriberHandlerMock_));
    
    handler.SendKeyEvent();
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent008
 * @tc.number: KeyCommandHandlerTest_SendKeyEvent_008
 * @tc.desc: Verify null subscriber handler safety
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent008, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    handler.count_ = 2;
    handler.launchAbilityCount_ = 0;
    
    EXPECT_CALL(*inputHandlerMock_, GetSubscriberHandler())
        .WillOnce(Return(nullptr));
    
    handler.SendKeyEvent();
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys001
 * @tc.number: KeyCommandHandlerTest_HandleShortKeys_001
 * @tc.desc: Verify returns false when no shortcut keys configured
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys001, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    KeyCommandHandler handler;
    handler.shortcutKeys_.clear();
    
    EXPECT_FALSE(handler.HandleShortKeys(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys002
 * @tc.number: KeyCommandHandlerTest_HandleShortKeys_002
 * @tc.desc: Verify skips when same key is waiting timeout
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys002, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    
    KeyCommandHandler handler;
    handler.shortcutKeys_.push_back({});
    handler.lastMatchedKey_.finalKey = KeyEvent::KEYCODE_A;
    handler.lastMatchedKey_.timerId = 100;
    
    EXPECT_CALL(handler, IsKeyMatch(_, _))
        .WillOnce(Return(true));
    
    EXPECT_TRUE(handler.HandleShortKeys(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys003
 * @tc.number: KeyCommandHandlerTest_HandleShortKeys_003
 * @tc.desc: Verify camera blocks VCR2 key
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys003, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VCR2);
    
    KeyCommandHandler handler;
    handler.shortcutKeys_.push_back({});
    
    // Camera in foreground
    EXPECT_CALL(*winMgrMock_, JudgeCaramaInFore())
        .WillOnce(Return(true));
    
    EXPECT_FALSE(handler.HandleShortKeys(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys004
 * @tc.number: KeyCommandHandlerTest_HandleShortKeys_004
 * @tc.desc: Verify skips when current ability key matches
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys004, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_B);
    
    KeyCommandHandler handler;
    handler.shortcutKeys_.push_back({});
    handler.currentLaunchAbilityKey_.finalKey = KeyEvent::KEYCODE_B;
    handler.currentLaunchAbilityKey_.timerId = 200;
    
    EXPECT_CALL(handler, IsKeyMatch(_, _))
        .WillOnce(Return(true));
    
    EXPECT_TRUE(handler.HandleShortKeys(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys005
 * @tc.number: KeyCommandHandlerTest_HandleShortKeys_005
 * @tc.desc: Verify removes pending timer before matching
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys005, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    
    KeyCommandHandler handler;
    handler.shortcutKeys_.push_back({});
    handler.lastMatchedKey_.timerId = 300;

    EXPECT_CALL(*timerMgrMock_, RemoveTimer(300)).Times(1);
    
    EXPECT_CALL(handler, MatchShortcutKeys(_))
        .WillOnce(Return(true));
    
    EXPECT_TRUE(handler.HandleShortKeys(keyEvent));
    EXPECT_EQ(handler.lastMatchedKey_.timerId, -1);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys006
 * @tc.number: KeyCommandHandlerTest_HandleShortKeys_006
 * @tc.desc: Verify shortcut match returns true
 */
TEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys006, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    
    KeyCommandHandler handler;
    handler.shortcutKeys_.push_back({});
    
    EXPECT_CALL(handler, MatchShortcutKeys(_))
        .WillOnce(Return(true));
    
    EXPECT_TRUE(handler.HandleShortKeys(keyEvent));
}
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
} // namespace MMI
} // namespace OHOS