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
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
} // namespace MMI
} // namespace OHOS