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
#include <memory>

#include "mmi_log.h"
#include "key_config_parser.h"
#include "test_key_command_service.h"
#include "key_command_handler_util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyConfigParserTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class KeyConfigParserTest : public testing::Test {
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
        handler_ = std::make_unique<KeyConfigParser>(context_, *service_);
    }

private:
    KeyCommandContext context_;
    std::unique_ptr<std::map<std::string, ShortcutKey>> shortcutKeys_;
    std::unique_ptr<std::vector<Sequence>> sequences_;
    std::unique_ptr<std::vector<RepeatKey>> repeatKeys_;
    std::unique_ptr<std::vector<ExcludeKey>> excludeKeys_;
    std::unique_ptr<TestKeyCommandService> service_;
    std::unique_ptr<KeyConfigParser> handler_;
};

/**
 * @tc.name: KeyConfigParserTest_KeyConfigParserPrint
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_KeyConfigParserPrint, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    Ability ability_temp;
    std::string copyShortcutKey = "copyShortcutKey";
    shortcutKey.preKeys.insert(2072);
    shortcutKey.finalKey = 2019;
    shortcutKey.keyDownDuration = 100;
    ability_temp.bundleName = "bundleName";
    ability_temp.abilityName = "abilityName";
    shortcutKey.ability = ability_temp;
    context_.shortcutKeys_->insert(std::make_pair(copyShortcutKey, shortcutKey));
    ASSERT_NO_FATAL_FAILURE(handler_->Print());
}

/**
 * @tc.name: KeyConfigParserTest_ParseJson_001
 * @tc.desc: Test the funcation ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseJson_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string configFile;
    bool ret = handler_->ParseJson(configFile);
    EXPECT_FALSE(ret);
    configFile = "config";
    std::string copyShortcutKey = "copyShortcutKey";
    ShortcutKey shortcutKey;
    Ability ability_temp;
    shortcutKey.preKeys.insert(2072);
    shortcutKey.finalKey = 2019;
    shortcutKey.keyDownDuration = 100;
    ability_temp.bundleName = "bundleName";
    ability_temp.abilityName = "abilityName";
    shortcutKey.ability = ability_temp;
    context_.shortcutKeys_->insert(std::make_pair(copyShortcutKey, shortcutKey));
    context_.businessIds_ = {"businessId"};
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.timerId = 1;
    ret = handler_->ParseJson(configFile);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyConfigParserTest_ParseJson_002
 * @tc.desc: Test the funcation ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseJson_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config.json";
    ASSERT_NO_FATAL_FAILURE(handler_->ParseJson(defaultConfig));
}

/**
 * @tc.name: KeyConfigParserTest_ParseJson_01
 * @tc.desc: Test ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseJson_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string configFile = "abc";
    std::string jsonStr = ReadJsonFile(configFile);

    jsonStr = "";
    bool ret = handler_->ParseJson(configFile);
    EXPECT_TRUE(jsonStr.empty());
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyConfigParserTest_ParseJson_02
 * @tc.desc: Test ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseJson_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string configFile = "config";
    std::string jsonStr = ReadJsonFile(configFile);

    jsonStr = "abc";
    bool ret = handler_->ParseJson(configFile);
    EXPECT_FALSE(jsonStr.empty());
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyConfigParserTest_GetBusinessId_001
 * @tc.desc: Test the function GetBusinessId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetBusinessId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateString("not an object");
    std::string businessIdValue;
    std::vector<std::string> businessIds;
    bool result = handler_->GetBusinessId(jsonData, businessIdValue, businessIds);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetBusinessId_002
 * @tc.desc: Test the function GetBusinessId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetBusinessId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "businessId", cJSON_CreateNumber(123));
    std::string businessIdValue;
    std::vector<std::string> businessIds;
    bool result = handler_->GetBusinessId(jsonData, businessIdValue, businessIds);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_001
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    ShortcutKey shortcutKey;
    bool result = handler_->GetPreKeys(jsonData, shortcutKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_002
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    for (int i = 0; i < MAX_PREKEYS_NUM + 1; ++i) {
        cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
    }
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    bool result = handler_->GetPreKeys(jsonData, shortcutKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_003
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "preKey", cJSON_CreateString("invalid"));
    ShortcutKey shortcutKey;
    bool result = handler_->GetPreKeys(jsonData, shortcutKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_004
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(-1));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    bool result = handler_->GetPreKeys(jsonData, shortcutKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_005
 * @tc.desc: Test the function GetPreKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    bool result = handler_->GetPreKeys(jsonData, shortcutKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetBusinessId_003
 * @tc.desc: Test the scenario where the JSON object is not a valid object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetBusinessId_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = nullptr;
    std::string businessIdValue;
    std::vector<std::string> businessIds;
    bool result = handler_->GetBusinessId(jsonData, businessIdValue, businessIds);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetBusinessId_004
 * @tc.desc: Test the scenario where businessId is not a string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetBusinessId_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    std::vector<std::string> businessIds;
    cJSON_AddItemToObject(jsonData, "businessIds", cJSON_CreateNumber(123));
    std::string businessIdValue;
    bool result = handler_->GetBusinessId(jsonData, businessIdValue, businessIds);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetBusinessId_005
 * @tc.desc: Test the normal running condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetBusinessId_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    std::vector<std::string> businessIds;
    cJSON_AddStringToObject(jsonData, "businessId", "testBusinessId");
    std::string businessIdValue;
    bool result = handler_->GetBusinessId(jsonData, businessIdValue, businessIds);
    EXPECT_TRUE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_006
 * @tc.desc: Test the case that the input jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    ShortcutKey shortcutKey;
    EXPECT_FALSE(handler_->GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_007
 * @tc.desc: Test the case that preKey is not an array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "preKey", cJSON_CreateString("test"));
    ShortcutKey shortcutKey;
    EXPECT_FALSE(handler_->GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_008
 * @tc.desc: Test the case that the size of preKey exceeds MAX_PREKEYS_NUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    for (int i = 0; i < 10; ++i) {
        cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
    }
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(handler_->GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_009
 * @tc.desc: Test if the element in preKey is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateString("not a number"));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(handler_->GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_010
 * @tc.desc: Tests if the number in preKey is less than 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(-1));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(handler_->GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_011
 * @tc.desc: Test the duplicated number in preKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    ShortcutKey shortcutKey;
    EXPECT_FALSE(handler_->GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetPreKeys_012
 * @tc.desc: Test the normal running condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetPreKeys_012, TestSize.Level1)
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
    EXPECT_TRUE(handler_->GetPreKeys(jsonData, shortcutKey));
    cJSON_Delete(jsonData);
}


/**
 * @tc.name: KeyConfigParserTest_GetTrigger_001
 * @tc.desc: Test jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetTrigger_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    const char* nonObjectInput = nullptr;
    EXPECT_FALSE(handler_->GetTrigger((const cJSON*)nonObjectInput, triggerType));
}

/**
 * @tc.name: KeyConfigParserTest_GetTrigger_002
 * @tc.desc: The value of the trigger field is not a string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetTrigger_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "trigger", cJSON_CreateNumber(123));
    EXPECT_FALSE(handler_->GetTrigger(jsonData, triggerType));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetTrigger_003
 * @tc.desc: The value of the test trigger field is neither key_up nor key_down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetTrigger_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "trigger", "invalid_value");
    EXPECT_FALSE(handler_->GetTrigger(jsonData, triggerType));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetTrigger_004
 * @tc.desc: The value of the test trigger field is key_up
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetTrigger_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "trigger", "key_up");
    EXPECT_TRUE(handler_->GetTrigger(jsonData, triggerType));
    EXPECT_EQ(triggerType, KeyEvent::KEY_ACTION_UP);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetTrigger_005
 * @tc.desc: The value of the test trigger field is key_down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetTrigger_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "trigger", "key_down");
    EXPECT_TRUE(handler_->GetTrigger(jsonData, triggerType));
    EXPECT_EQ(triggerType, KeyEvent::KEY_ACTION_DOWN);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyDownDuration_001
 * @tc.desc: Test jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyDownDuration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyDownDurationInt = 1;
    EXPECT_FALSE(handler_->GetKeyDownDuration(nullptr, keyDownDurationInt));
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyDownDuration_002
 * @tc.desc: Test that the value of the keyDownDuration field is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyDownDuration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "keyDownDuration", cJSON_CreateString("not a number"));
    int32_t keyDownDurationInt = 1;
    EXPECT_FALSE(handler_->GetKeyDownDuration(jsonData, keyDownDurationInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyDownDuration_003
 * @tc.desc: Test the value of the keyDownDuration field is negative
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyDownDuration_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyDownDuration", -1);
    int32_t keyDownDurationInt = 1;
    EXPECT_FALSE(handler_->GetKeyDownDuration(jsonData, keyDownDurationInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyDownDuration_004
 * @tc.desc: Test normal branch condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyDownDuration_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyDownDuration", 1);
    int32_t keyDownDurationInt = 1;
    EXPECT_TRUE(handler_->GetKeyDownDuration(jsonData, keyDownDurationInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyFinalKey_001
 * @tc.desc: Test jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyFinalKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t finalKeyInt = 1;
    EXPECT_FALSE(handler_->GetKeyFinalKey(nullptr, finalKeyInt));
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyFinalKey_002
 * @tc.desc: Test finalKey value is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyFinalKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t finalKeyInt = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "finalKey", "not a number");
    EXPECT_FALSE(handler_->GetKeyFinalKey(jsonData, finalKeyInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyFinalKey_003
 * @tc.desc: Test that jsonData is an object and that the value of finalKey is a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyFinalKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t finalKeyInt = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "finalKey", 123);
    EXPECT_TRUE(handler_->GetKeyFinalKey(jsonData, finalKeyInt));
    EXPECT_EQ(finalKeyInt, 123);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_001
 * @tc.desc: The test case jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = nullptr;
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_002
 * @tc.desc: Test case 2 GetBusinessId failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_003
 * @tc.desc: Test case 3 GetPreKeys failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "businessId", "test");
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_004
 * @tc.desc: Test case 4 GetKeyFinalKey failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "businessId", "test");
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(3));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(4));
    cJSON_AddItemToObject(jsonData, "preKeys", cJSON_CreateArray());
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_005
 * @tc.desc: Test case 5 GetTrigger failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "businessId", "test");
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(3));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(4));
    cJSON_AddItemToObject(jsonData, "preKeys", cJSON_CreateArray());
    cJSON_AddNumberToObject(jsonData, "finalKey", 123);
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_006
 * @tc.desc: Test case 6 GetKeyDownDuration failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "businessId", "test");
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(3));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(4));
    cJSON_AddItemToObject(jsonData, "preKeys", cJSON_CreateArray());
    cJSON_AddNumberToObject(jsonData, "finalKey", 123);
    cJSON_AddStringToObject(jsonData, "trigger", "key_down");
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_007
 * @tc.desc: Test case 7 Ability is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "businessId", "test");
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(3));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(4));
    cJSON_AddItemToObject(jsonData, "preKeys", cJSON_CreateArray());
    cJSON_AddNumberToObject(jsonData, "finalKey", 123);
    cJSON_AddStringToObject(jsonData, "trigger", "key_down");
    cJSON_AddNumberToObject(jsonData, "keyDownDuration", 1);
    cJSON_AddItemToObject(jsonData, "statusConfig", cJSON_CreateString("test"));
    cJSON_AddItemToObject(jsonData, "ability", cJSON_CreateString("test"));
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToShortcutKey_008
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToShortcutKey_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "businessId", "test");
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonData, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(3));
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(4));
    cJSON_AddItemToObject(jsonData, "preKeys", cJSON_CreateArray());
    cJSON_AddNumberToObject(jsonData, "finalKey", 123);
    cJSON_AddStringToObject(jsonData, "trigger", "key_down");
    cJSON_AddNumberToObject(jsonData, "keyDownDuration", 1);
    cJSON_AddItemToObject(jsonData, "statusConfig", cJSON_CreateString("test"));
    cJSON *ability = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "ability", ability);
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = handler_->ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_TRUE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyCode_001
 * @tc.desc: The test case jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyCode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = nullptr;
    int32_t keyCodeInt;
    bool result = handler_->GetKeyCode(jsonData, keyCodeInt);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyCode_002
 * @tc.desc: Test that the value of the keyCode field is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyCode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"otherKey\": \"value\"}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    int32_t keyCodeInt;
    bool result = handler_->GetKeyCode(jsonData, keyCodeInt);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyCode_003
 * @tc.desc: The value of the test keyCode field is negative
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyCode_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"keyCode\": -123}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    int32_t keyCodeInt;
    bool result = handler_->GetKeyCode(jsonData, keyCodeInt);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyCode_004
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyCode_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"keyCode\": 123}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    int32_t keyCodeInt;
    bool result = handler_->GetKeyCode(jsonData, keyCodeInt);
    EXPECT_TRUE(result);
    EXPECT_EQ(keyCodeInt, 123);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyAction_001
 * @tc.desc: The test case jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const cJSON* jsonData = nullptr;
    int32_t keyActionInt;
    EXPECT_FALSE(handler_->GetKeyAction(jsonData, keyActionInt));
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyAction_002
 * @tc.desc: The value of the test keyAction field is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyAction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "keyAction", cJSON_CreateString("down"));
    int32_t keyActionInt;
    EXPECT_FALSE(handler_->GetKeyAction(jsonData, keyActionInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyAction_003
 * @tc.desc: The value of the Test Caiaction field is 999
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyAction_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyAction", 999);
    int32_t keyActionInt;
    EXPECT_FALSE(handler_->GetKeyAction(jsonData, keyActionInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetKeyAction_004
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetKeyAction_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyAction", KeyEvent::KEY_ACTION_DOWN);
    int32_t keyActionInt;
    EXPECT_TRUE(handler_->GetKeyAction(jsonData, keyActionInt));
    EXPECT_EQ(keyActionInt, KeyEvent::KEY_ACTION_DOWN);
    cJSON_Delete(jsonData);
}


/**
 * @tc.name: KeyConfigParserTest_GetDelay_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    int64_t delayInt = 1;
    EXPECT_FALSE(handler_->GetDelay(jsonData, delayInt));
}

/**
 * @tc.name: KeyConfigParserTest_GetDelay_002
 * @tc.desc: Tests the condition when the delay entry is present but not numeric
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetDelay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "delay", cJSON_CreateString("not a number"));
    int64_t delayInt = 1;
    EXPECT_FALSE(handler_->GetDelay(jsonData, delayInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetDelay_003
 * @tc.desc: Tests the case when the delay term is a negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetDelay_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "delay", -1);
    int64_t delayInt = 1;
    EXPECT_FALSE(handler_->GetDelay(jsonData, delayInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetDelay_004
 * @tc.desc: Test the condition when all conditions are met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetDelay_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "delay", 10);
    int64_t delayInt = 1;
    EXPECT_TRUE(handler_->GetDelay(jsonData, delayInt));
    EXPECT_EQ(delayInt, 10 * SECONDS_SYSTEM);
    cJSON_Delete(jsonData);
}


/**
 * @tc.name: KeyConfigParserTest_GetRepeatTimes_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetRepeatTimes_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(handler_->GetRepeatTimes(nullptr, repeatTimesInt));
}

/**
 * @tc.name: KeyConfigParserTest_GetRepeatTimes_002
 * @tc.desc: Tests the case when the delay term is a negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetRepeatTimes_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "times", cJSON_CreateString("not a number"));
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(handler_->GetRepeatTimes(jsonData, repeatTimesInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetRepeatTimes_003
 * @tc.desc: Test the case when the timers entry is a negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetRepeatTimes_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "times", cJSON_CreateNumber(-1));
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(handler_->GetRepeatTimes(jsonData, repeatTimesInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetRepeatTimes_004
 * @tc.desc: Test the condition when all conditions are met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetRepeatTimes_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "times", cJSON_CreateNumber(1));
    int32_t repeatTimesInt = 1;
    EXPECT_TRUE(handler_->GetRepeatTimes(jsonData, repeatTimesInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_PackageSequenceKey_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_PackageSequenceKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* json = nullptr;
    SequenceKey sequenceKey;
    bool result = handler_->PackageSequenceKey(json, sequenceKey);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: KeyConfigParserTest_PackageSequenceKey_002
 * @tc.desc: Tests get keyCode failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_PackageSequenceKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"otherKey\": \"value\"}";
    cJSON *json = cJSON_Parse(jsonStr);
    SequenceKey sequenceKey;
    bool result = handler_->PackageSequenceKey(json, sequenceKey);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: KeyConfigParserTest_PackageSequenceKey_003
 * @tc.desc: Tests get keyAction failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_PackageSequenceKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"keyCode\": 123}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    SequenceKey sequenceKey;
    bool result = handler_->PackageSequenceKey(jsonData, sequenceKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetSequenceKeys_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetSequenceKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    Sequence sequence;
    bool result = handler_->GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetSequenceKeys_002
 * @tc.desc: Tests sequenceKeys number must be array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetSequenceKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "sequenceKeys", cJSON_CreateString("invalid"));
    Sequence sequence;
    bool result = handler_->GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetSequenceKeys_003
 * @tc.desc: Tests sequenceKeysSize number must less
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetSequenceKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* sequenceKeys = cJSON_CreateArray();
    for (int i = 0; i <= MAX_SEQUENCEKEYS_NUM; ++i) {
        cJSON* sequenceKeyJson = cJSON_CreateObject();
        cJSON_AddItemToObject(sequenceKeyJson, "key", cJSON_CreateString("key"));
        cJSON_AddItemToArray(sequenceKeys, sequenceKeyJson);
    }
    cJSON_AddItemToObject(jsonData, "sequenceKeys", sequenceKeys);
    Sequence sequence;
    bool result = handler_->GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetSequenceKeys_004
 * @tc.desc: Tests packege sequenceKey failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetSequenceKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* sequenceKeys = cJSON_CreateArray();
    for (int i = 0; i < MAX_SEQUENCEKEYS_NUM; ++i) {
        cJSON* sequenceKeyJson = cJSON_CreateObject();
        cJSON_AddItemToObject(sequenceKeyJson, "key", cJSON_CreateString("key"));
        cJSON_AddItemToArray(sequenceKeys, sequenceKeyJson);
    }
    cJSON_AddItemToObject(jsonData, "sequenceKeys", sequenceKeys);
    Sequence sequence;
    bool result = handler_->GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}


/**
 * @tc.name: KeyConfigParserTest_IsSequenceKeysValid_001
 * @tc.desc: Test case check when sequenceKeys is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_IsSequenceKeysValid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.sequenceKeys = {};
    EXPECT_FALSE(handler_->IsSequenceKeysValid(sequence));
}

/**
 * @tc.name: KeyConfigParserTest_IsSequenceKeysValid_002
 * @tc.desc: Test cases check when the size of sequenceKeys exceeds the maximum limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_IsSequenceKeysValid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.sequenceKeys.resize(MAX_SEQUENCEKEYS_NUM + 1);
    EXPECT_FALSE(handler_->IsSequenceKeysValid(sequence));
}

/**
 * @tc.name: KeyConfigParserTest_IsSequenceKeysValid_003
 * @tc.desc: Test cases check when there are duplicate keys in sequenceKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_IsSequenceKeysValid_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    SequenceKey key1;
    key1.keyCode = 1;
    key1.delay = 0;
    sequence.sequenceKeys.push_back(key1);
    SequenceKey key2;
    key2.keyCode = 1;
    key2.delay = 0;
    sequence.sequenceKeys.push_back(key2);
    EXPECT_FALSE(handler_->IsSequenceKeysValid(sequence));
}

/**
 * @tc.name: KeyConfigParserTest_IsSequenceKeysValid_004
 * @tc.desc: Test cases check when sequenceKeys are valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_IsSequenceKeysValid_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    SequenceKey key1;
    key1.keyCode = 1;
    key1.delay = 0;
    sequence.sequenceKeys.push_back(key1);
    SequenceKey key2;
    key2.keyCode = 2;
    key2.delay = 0;
    sequence.sequenceKeys.push_back(key2);
    EXPECT_TRUE(handler_->IsSequenceKeysValid(sequence));
}


/**
 * @tc.name: KeyConfigParserTest_ConvertToKeySequence_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToKeySequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    Sequence sequence;
    EXPECT_FALSE(handler_->ConvertToKeySequence(jsonData, sequence));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToKeySequence_002
 * @tc.desc: Tests Get sequenceKeys failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToKeySequence_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    Sequence sequence;
    cJSON_AddItemToObject(jsonData, "sequenceKeys", cJSON_CreateString("invalid"));
    EXPECT_FALSE(handler_->ConvertToKeySequence(jsonData, sequence));
    cJSON_Delete(jsonData);
}


/**
 * @tc.name: KeyConfigParserTest_ConvertToExcludeKey_001
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToExcludeKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "keyCode", cJSON_CreateString("not a number"));
    ExcludeKey exKey;
    EXPECT_FALSE(handler_->ConvertToExcludeKey(jsonData, exKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToExcludeKey_002
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToExcludeKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "keyAction", cJSON_CreateString("not a number"));
    ExcludeKey exKey;
    bool ret = handler_->ConvertToExcludeKey(jsonData, exKey);
    EXPECT_FALSE(ret);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToExcludeKey_003
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToExcludeKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "delay", cJSON_CreateString("not a number"));
    ExcludeKey exKey;
    EXPECT_FALSE(handler_->ConvertToExcludeKey(jsonData, exKey));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToExcludeKey_004
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToExcludeKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    ExcludeKey exKey;
    EXPECT_FALSE(handler_->ConvertToExcludeKey(parser.Get(), exKey));
}


/**
 * @tc.name: KeyConfigParserTest_GetRepeatTimes_005
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetRepeatTimes_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(handler_->GetRepeatTimes(jsonData, repeatTimesInt));
}

/**
 * @tc.name: KeyConfigParserTest_GetRepeatTimes_006
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetRepeatTimes_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "repeatTimes", cJSON_CreateString("not a number"));
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(handler_->GetRepeatTimes(jsonData, repeatTimesInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_GetRepeatTimes_007
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_GetRepeatTimes_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "repeatTimes", -1);
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(handler_->GetRepeatTimes(jsonData, repeatTimesInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToKeyRepeat_001
 * @tc.desc: Test for preNotifyAbility is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToKeyRepeat_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyCode", 1);
    cJSON_AddNumberToObject(jsonData, "times", 2);
    cJSON_AddNumberToObject(jsonData, "delay", 3);
    cJSON_AddStringToObject(jsonData, "statusConfig", "test");
    cJSON *ability = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "ability", ability);
    RepeatKey repeatKey;
    bool result = handler_->ConvertToKeyRepeat(jsonData, repeatKey);
    EXPECT_TRUE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToKeyRepeat_002
 * @tc.desc: Test for preNotifyAbility is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToKeyRepeat_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyCode", 1);
    cJSON_AddNumberToObject(jsonData, "times", 2);
    cJSON_AddNumberToObject(jsonData, "delay", 3);
    cJSON_AddStringToObject(jsonData, "statusConfig", "test");
    cJSON *ability = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "ability", ability);
    cJSON_AddItemToObject(jsonData, "preNotifyAbility", cJSON_CreateString("test"));
    RepeatKey repeatKey;
    bool result = handler_->ConvertToKeyRepeat(jsonData, repeatKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ConvertToKeyRepeat_003
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ConvertToKeyRepeat_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyCode", 1);
    cJSON_AddNumberToObject(jsonData, "times", 2);
    cJSON_AddNumberToObject(jsonData, "delay", 3);
    cJSON_AddStringToObject(jsonData, "statusConfig", "test");
    cJSON *ability = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "ability", ability);
    cJSON *preNotifyAbility = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "preNotifyAbility", preNotifyAbility);
    RepeatKey repeatKey;
    bool result = handler_->ConvertToKeyRepeat(jsonData, repeatKey);
    EXPECT_TRUE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyConfigParserTest_ParseShortcutKeys_001
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseShortcutKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    std::map<std::string, ShortcutKey> shortcutKeys;
    std::vector<std::string> businessIds;
    EXPECT_FALSE(handler_->ParseShortcutKeys(parser, shortcutKeys, businessIds));
}

/**
 * @tc.name: KeyConfigParserTest_ParseSequences_001
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseSequences_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    std::vector<Sequence> sequences;
    EXPECT_FALSE(handler_->ParseSequences(parser, sequences));
}

/**
 * @tc.name: KeyConfigParserTest_ParseExcludeKeys_001
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseExcludeKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    std::vector<ExcludeKey> excludeKeys;
    EXPECT_FALSE(handler_->ParseExcludeKeys(parser, excludeKeys));
}


/**
 * @tc.name: KeyConfigParserTest_ParseRepeatKeys_001
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseRepeatKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    std::vector<RepeatKey> repeatKeys;
    std::map<int32_t, int32_t> repeatKeyMaxTimes;
    EXPECT_FALSE(handler_->ParseRepeatKeys(parser, repeatKeys, repeatKeyMaxTimes));
}


/**
 * @tc.name: KeyConfigParserTest_ParseTwoFingerGesture_001
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyConfigParserTest, KeyConfigParserTest_ParseTwoFingerGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    TwoFingerGesture twoFingerGesture;
    EXPECT_FALSE(handler_->ParseTwoFingerGesture(parser, twoFingerGesture));
}
} // namespace MMI
} // namespace OHOS