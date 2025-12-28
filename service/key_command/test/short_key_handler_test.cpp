/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "event_log_helper.h"
#include "mmi_log.h"
#include "short_key_handler.h"
#include "test_key_command_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ShortKeyHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t ERROR_DELAY_VALUE = -1000;
} // namespace
class ShortKeyHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() override
    {
        shortcutKeys_ = std::make_unique<std::map<std::string, ShortcutKey>>();
        sequences_ = std::make_unique<std::vector<Sequence>>();
        repeatKeys_ = std::make_unique<std::vector<RepeatKey>>();
        excludeKeys_ = std::make_unique<std::vector<ExcludeKey>>();

        context_.shortcutKeys_ = shortcutKeys_.get();
        context_.sequences_ = sequences_.get();
        context_.repeatKeys_ = repeatKeys_.get();
        context_.excludeKeys_ = excludeKeys_.get();

        service_ = std::make_unique<TestKeyCommandService>();  
        handler_ = std::make_unique<ShortKeyHandler>(context_, *service_);
    }

    void TearDown() override
    {
        handler_.reset();
        service_.reset();
        shortcutKeys_.reset();
        sequences_.reset();
        repeatKeys_.reset();
        excludeKeys_.reset();
    }

private:
    KeyCommandContext context_;
    std::unique_ptr<std::map<std::string, ShortcutKey>> shortcutKeys_;
    std::unique_ptr<std::vector<Sequence>> sequences_;
    std::unique_ptr<std::vector<RepeatKey>> repeatKeys_;
    std::unique_ptr<std::vector<ExcludeKey>> excludeKeys_;
    std::unique_ptr<TestKeyCommandService> service_;
    std::unique_ptr<ShortKeyHandler> handler_;
};

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_001
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "config1";
    key.statusConfigValue = true;
    key.finalKey = 4;
    key.keyDownDuration = 5;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName1";
    ability_temp.abilityName = "abilityName1";
    key.ability = ability_temp;
    context_.shortcutKeys_->insert(std::make_pair("key1", key));
    handler_->lastMatchedKeys_.insert("key1");
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    std::string businessId = "power";
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_002
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business2";
    key.statusConfig = "config2";
    key.statusConfigValue = true;
    key.finalKey = 5;
    key.keyDownDuration = 6;
    key.triggerType = KeyEvent::KEY_ACTION_UP;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName2";
    ability_temp.abilityName = "abilityName2";
    key.ability = ability_temp;
    context_.shortcutKeys_->insert(std::make_pair("key2", key));
    handler_->lastMatchedKeys_.insert("key2");
    bool ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    std::string businessId = "power";
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_003
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business3";
    key.statusConfig = "config3";
    key.statusConfigValue = true;
    key.finalKey = 7;
    key.keyDownDuration = 8;
    key.triggerType = KeyEvent::KEY_ACTION_CANCEL;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName3";
    ability_temp.abilityName = "abilityName3";
    key.ability = ability_temp;
    context_.shortcutKeys_->insert(std::make_pair("key3", key));
    handler_->lastMatchedKeys_.insert("key3");
    bool ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    std::string businessId = "power";
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_004
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_004, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "config1";
    key.statusConfigValue = true;
    key.finalKey = 4;
    key.keyDownDuration = 5;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 6;
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(2);
    context_.shortcutKeys_->insert(std::make_pair("key1", key));
    handler_->lastMatchedKeys_.insert("key1");
    bool ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_005
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_005, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "config1";
    key.statusConfigValue = true;
    key.finalKey = 4;
    key.keyDownDuration = 5;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 6;
    handler_->currentLaunchAbilityKey_.finalKey = 1;
    handler_->currentLaunchAbilityKey_.triggerType = 2;
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(2);
    bool result = handler_->IsKeyMatch(handler_->currentLaunchAbilityKey_, keyEvent);
    ASSERT_FALSE(result);
    context_.shortcutKeys_->insert(std::make_pair("key1", key));
    handler_->currentLaunchAbilityKey_.timerId = 0;
    bool ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler_->currentLaunchAbilityKey_.timerId = -1;
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler_->currentLaunchAbilityKey_.timerId = 0;
    handler_->currentLaunchAbilityKey_.finalKey = 1;
    handler_->currentLaunchAbilityKey_.triggerType = 2;
    keyEvent->SetKeyCode(3);
    keyEvent->SetKeyAction(4);
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler_->currentLaunchAbilityKey_.timerId = -1;
    handler_->currentLaunchAbilityKey_.finalKey = 1;
    handler_->currentLaunchAbilityKey_.triggerType = 2;
    keyEvent->SetKeyCode(3);
    keyEvent->SetKeyAction(4);
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_006
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_006, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {2, 3, 4};
    key.businessId = "business";
    key.statusConfig = "config";
    key.statusConfigValue = true;
    key.finalKey = 6;
    key.keyDownDuration = 7;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 10;
    context_.shortcutKeys_->insert(std::make_pair("key1", key));
    bool ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);

    handler_->currentLaunchAbilityKey_.businessId = "business1";
    handler_->currentLaunchAbilityKey_.statusConfig = "config1";
    handler_->currentLaunchAbilityKey_.timerId = 6;
    handler_->currentLaunchAbilityKey_.statusConfigValue = true;
    handler_->currentLaunchAbilityKey_.finalKey = 4;
    handler_->currentLaunchAbilityKey_.keyDownDuration = 5;
    handler_->currentLaunchAbilityKey_.triggerType = KeyEvent::KEY_ACTION_DOWN;
    keyEvent->SetKeyCode(KeyEvent::INTENTION_RIGHT);
    keyEvent->SetKeyAction(KeyEvent::INTENTION_UP);
    EventLogHelper eventLogHelper;
    eventLogHelper.userType_ = "beta";
    keyEvent->bitwise_ = 0x00000040;
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    eventLogHelper.userType_ = "abcde";
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    keyEvent->bitwise_ = 0x00000000;
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler_->lastMatchedKeys_ = {};
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_007
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business2";
    key.statusConfig = "config2";
    key.statusConfigValue = true;
    key.finalKey = 5;
    key.keyDownDuration = 6;
    key.triggerType = KeyEvent::KEY_ACTION_UP;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName2";
    ability_temp.abilityName = "abilityName2";
    key.ability = ability_temp;
    context_.shortcutKeys_->insert(std::make_pair("key2", key));
    handler_->lastMatchedKeys_.insert("key2");
    bool ret = handler_->HandleShortKeys(keyEvent);
    EXPECT_FALSE(ret);

    key.businessId = "power";
    int32_t delay = handler_->GetKeyDownDurationFromXml(key.businessId);
    EXPECT_TRUE(delay < 0);
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    ret = handler_->HandleShortKeys(keyEvent);
    EXPECT_FALSE(ret);

    key.triggerType = KeyEvent::KEY_ACTION_UP;
    bool handleResult = handler_->HandleKeyUp(keyEvent, key);
    EXPECT_FALSE(handleResult);
    ret = handler_->HandleShortKeys(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleShortKeys_008
 * @tc.desc: Test the funcation HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleShortKeys_008, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {2};
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 6;
    shortcutKey.keyDownDuration = 7;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    shortcutKey.timerId = 10;
    context_.shortcutKeys_->insert(std::make_pair("key", shortcutKey));
    handler_->lastMatchedKeys_.insert("key");
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(3);
    item1.SetDownTime(5);
    item1.SetDeviceId(8);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(3);
    item2.SetDownTime(6);
    item2.SetDeviceId(4);
    keyEvent->AddKeyItem(item1);
    keyEvent->AddKeyItem(item2);
    bool ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);

    handler_->currentLaunchAbilityKey_.timerId = 5;
    handler_->currentLaunchAbilityKey_.finalKey = 1;
    handler_->currentLaunchAbilityKey_.triggerType = KeyEvent::KEY_ACTION_UP;
    handler_->currentLaunchAbilityKey_.preKeys = {3};
    EventLogHelper eventLogHelper;
    eventLogHelper.userType_ = "beta";
    keyEvent->bitwise_ = InputEvent::EVENT_FLAG_PRIVACY_MODE;
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_TRUE(ret);
    eventLogHelper.userType_ = "aaaaaaa";
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_TRUE(ret);
    keyEvent->bitwise_ = 0;
    ret = handler_->HandleShortKeys(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_MatchShortcutKey_001
 * @tc.desc: Test the funcation MatchShortcutKey
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_MatchShortcutKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(6);
    keyEvent->SetKeyAction(3);
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {3, 2, 4};
    shortcutKey.businessId = "businessId1";
    shortcutKey.statusConfig = "statusConfig1";
    shortcutKey.statusConfigValue = false;
    shortcutKey.finalKey = 6;
    shortcutKey.keyDownDuration = 9;
    shortcutKey.triggerType = 1;
    shortcutKey.timerId = 3;
    std::vector<ShortcutKey> upAbilities;
    upAbilities.push_back(shortcutKey);
    bool ret = handler_->MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_MatchShortcutKey_002
 * @tc.desc: Test the funcation MatchShortcutKey
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_MatchShortcutKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(5);
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {1, 2, 3};
    shortcutKey.businessId = "businessId";
    shortcutKey.statusConfig = "statusConfig";
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 5;
    shortcutKey.keyDownDuration = 1;
    shortcutKey.triggerType = 10;
    shortcutKey.timerId = 1;
    std::vector<ShortcutKey> upAbilities;
    upAbilities.push_back(shortcutKey);
    bool ret = handler_->MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_IsKeyMatch
 * @tc.desc: IsKeyMatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_IsKeyMatch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    shortcutKey.finalKey = 2019;
    shortcutKey.preKeys.insert(2072);
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    item.SetKeyCode(KeyEvent::KEYCODE_C);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_FALSE(handler_->IsKeyMatch(shortcutKey, keyEvent));

    shortcutKey.preKeys.insert(2047);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_E);
    keyEvent->AddKeyItem(item);
    ASSERT_FALSE(handler_->IsKeyMatch(shortcutKey, keyEvent));
}

/**
 * @tc.name: ShortKeyHandlerTest_SkipFinalKey
 * @tc.desc: Skip Final Key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_SkipFinalKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1024;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_FALSE(handler_->SkipFinalKey(keyCode, keyEvent));
}

// /**
//  * @tc.name: ShortKeyHandlerTest_HandleKeyDown_01
//  * @tc.desc: Handle Key Down
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyDown_01, TestSize.Level1)
// {
//     CALL_TEST_DEBUG;
//     ShortcutKey shortcutKey;
//     shortcutKey.keyDownDuration = 0;
//     shortcutKey.ability.bundleName = "com.example.test";
//     ASSERT_TRUE(handler_->HandleKeyDown(shortcutKey));
// }

// /**
//  * @tc.name: ShortKeyHandlerTest_HandleKeyDown_02
//  * @tc.desc: test HandleKeyDown
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyDown_02, TestSize.Level1)
// {
//     CALL_TEST_DEBUG;
//     ShortcutKey shortcutKey;
//     shortcutKey.keyDownDuration = 1000;
//     shortcutKey.ability.bundleName = "com.example.test";
//     shortcutKey.timerId = -1;
//     ASSERT_FALSE(handler_->HandleKeyDown(shortcutKey));
// }

// /**
//  * @tc.name: ShortKeyHandlerTest_HandleKeyDown_03
//  * @tc.desc: test HandleKeyDown
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyDown_03, TestSize.Level1)
// {
//     CALL_TEST_DEBUG;
//     ShortcutKey shortcutKey;
//     shortcutKey.keyDownDuration = 0;
//     shortcutKey.ability.bundleName = "com.example.test";
//     shortcutKey.timerId = -1;
//     ASSERT_TRUE(handler_->HandleKeyDown(shortcutKey));
// }

// /**
//  * @tc.name: ShortKeyHandlerTest_HandleKeyDown_04
//  * @tc.desc: test HandleKeyDown
//  * @tc.type: FUNC
//  * @tc.require:
//  */
// HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyDown_04, TestSize.Level1)
// {
//     CALL_TEST_DEBUG;
//     ShortcutKey shortcutKey;
//     shortcutKey.keyDownDuration = 1000;
//     shortcutKey.ability.bundleName = "com.example.test";
//     shortcutKey.finalKey = 17;
//     shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
//     ASSERT_FALSE(handler_->HandleKeyDown(shortcutKey));
// }

/**
 * @tc.name: ShortKeyHandlerTest_HandleKeyUp_001
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 0;
    ASSERT_TRUE(handler_->HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleKeyUp_002
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 1;
    ASSERT_FALSE(handler_->HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleKeyUp_003
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyUp_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 1;
    item.SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->SetActionTime(10000);
    ASSERT_TRUE(handler_->HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleKeyUp_004
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyUp_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 10;
    item.SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->SetActionTime(100);
    ASSERT_FALSE(handler_->HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleKeyCancel
 * @tc.desc: HandleKeyCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleKeyCancel, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    shortcutKey.timerId = -1;
    ASSERT_FALSE(handler_->HandleKeyCancel(shortcutKey));
    shortcutKey.timerId = 10;
    ASSERT_FALSE(handler_->HandleKeyCancel(shortcutKey));
}

/**
 * @tc.name: ShortKeyHandlerTest_HandleConsumedKeyEvent
 * @tc.desc: Test the funcation HandleConsumedKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_HandleConsumedKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    ShortcutKey testKey;
    testKey.finalKey = -1;
    handler_->currentLaunchAbilityKey_ = testKey;
    int32_t keyCode = -1;
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool ret = handler_->HandleConsumedKeyEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ShortKeyHandlerTest_GetKeyDownDurationFromXml
 * @tc.desc: GetKeyDownDurationFromXml
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ShortKeyHandlerTest, ShortKeyHandlerTest_GetKeyDownDurationFromXml, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string businessId = "power";
    int32_t ret = handler_->GetKeyDownDurationFromXml(businessId);
    ASSERT_EQ(ret, ERROR_DELAY_VALUE);
}
} // namespace MMI
} // namespace OHOS