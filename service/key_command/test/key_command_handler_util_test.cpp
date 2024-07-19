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
    for (int32_t i = 0; i < MAX_PREKEYS_NUM + 1; ++i) {
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
    EXPECT_TRUE(OHOS::MMI::IsSpecialType(keyCode, type));
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
    for (int32_t i = 0; i < 10; ++i) {
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

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetTrigger_001
 * @tc.desc: Test jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetTrigger_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    const char* nonObjectInput = nullptr;
    EXPECT_FALSE(OHOS::MMI::GetTrigger((const cJSON*)nonObjectInput, triggerType));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetTrigger_002
 * @tc.desc: The value of the trigger field is not a string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetTrigger_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "trigger", cJSON_CreateNumber(123));
    EXPECT_FALSE(OHOS::MMI::GetTrigger(jsonData, triggerType));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetTrigger_003
 * @tc.desc: The value of the test trigger field is neither key_up nor key_down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetTrigger_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "trigger", "invalid_value");
    EXPECT_FALSE(OHOS::MMI::GetTrigger(jsonData, triggerType));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetTrigger_004
 * @tc.desc: The value of the test trigger field is key_up
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetTrigger_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "trigger", "key_up");
    EXPECT_TRUE(OHOS::MMI::GetTrigger(jsonData, triggerType));
    EXPECT_EQ(triggerType, KeyEvent::KEY_ACTION_UP);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetTrigger_005
 * @tc.desc: The value of the test trigger field is key_down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetTrigger_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t triggerType = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "trigger", "key_down");
    EXPECT_TRUE(OHOS::MMI::GetTrigger(jsonData, triggerType));
    EXPECT_EQ(triggerType, KeyEvent::KEY_ACTION_DOWN);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyDownDuration_001
 * @tc.desc: Test jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyDownDuration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyDownDurationInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetKeyDownDuration(nullptr, keyDownDurationInt));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyDownDuration_002
 * @tc.desc: Test that the value of the keyDownDuration field is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyDownDuration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "keyDownDuration", cJSON_CreateString("not a number"));
    int32_t keyDownDurationInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetKeyDownDuration(jsonData, keyDownDurationInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyDownDuration_003
 * @tc.desc: Test the value of the keyDownDuration field is negative
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyDownDuration_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyDownDuration", -1);
    int32_t keyDownDurationInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetKeyDownDuration(jsonData, keyDownDurationInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyDownDuration_004
 * @tc.desc: Test normal branch condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyDownDuration_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyDownDuration", 1);
    int32_t keyDownDurationInt = 1;
    EXPECT_TRUE(OHOS::MMI::GetKeyDownDuration(jsonData, keyDownDurationInt));
    EXPECT_EQ(keyDownDurationInt, 1);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyFinalKey_001
 * @tc.desc: Test jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyFinalKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t finalKeyInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetKeyFinalKey(nullptr, finalKeyInt));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyFinalKey_002
 * @tc.desc: Test finalKey value is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyFinalKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t finalKeyInt = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "finalKey", "not a number");
    EXPECT_FALSE(OHOS::MMI::GetKeyFinalKey(jsonData, finalKeyInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyFinalKey_003
 * @tc.desc: Test that jsonData is an object and that the value of finalKey is a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyFinalKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t finalKeyInt = 1;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "finalKey", 123);
    EXPECT_TRUE(OHOS::MMI::GetKeyFinalKey(jsonData, finalKeyInt));
    EXPECT_EQ(finalKeyInt, 123);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyVal_001
 * @tc.desc: Test key does not exist in JSON object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyVal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *json = nullptr;
    std::string value;
    OHOS::MMI::GetKeyVal(json, "key", value);
    EXPECT_TRUE(value.empty());
    cJSON_Delete(json);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyVal_002
 * @tc.desc: The value corresponding to the test key is a string type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyVal_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "key", "value");
    std::string value;
    OHOS::MMI::GetKeyVal(json, "key", value);
    EXPECT_EQ(value, "value");
    cJSON_Delete(json);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetEntities_001
 * @tc.desc: Testing jsonAbility is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetEntities_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = nullptr;
    ASSERT_FALSE(OHOS::MMI::GetEntities(jsonAbility, ability));
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetEntities_002
 * @tc.desc: Test has no entities field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetEntities_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    ASSERT_TRUE(OHOS::MMI::GetEntities(jsonAbility, ability));
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetEntities_003
 * @tc.desc: The test entities field exists but is not an array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetEntities_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonAbility, "entities", cJSON_CreateNumber(123));
    ASSERT_FALSE(OHOS::MMI::GetEntities(jsonAbility, ability));
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetEntities_004
 * @tc.desc: Test array contains non-string elements
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetEntities_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    cJSON* entities = cJSON_CreateArray();
    cJSON_AddItemToArray(entities, cJSON_CreateNumber(123));
    cJSON_AddItemToObject(jsonAbility, "entities", entities);
    ASSERT_FALSE(OHOS::MMI::GetEntities(jsonAbility, ability));
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetEntities_005
 * @tc.desc: Test normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetEntities_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    cJSON* entities = cJSON_CreateArray();
    cJSON_AddItemToArray(entities, cJSON_CreateString("entity1"));
    cJSON_AddItemToArray(entities, cJSON_CreateString("entity2"));
    cJSON_AddItemToObject(jsonAbility, "entities", entities);
    ASSERT_TRUE(OHOS::MMI::GetEntities(jsonAbility, ability));
    EXPECT_EQ(ability.entities.size(), 2);
    EXPECT_EQ(ability.entities[0], "entity1");
    EXPECT_EQ(ability.entities[1], "entity2");
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetParams_001
 * @tc.desc: Test jsonAbility is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetParams_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = nullptr;
    ASSERT_FALSE(OHOS::MMI::GetParams(jsonAbility, ability));
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetParams_002
 * @tc.desc: Test params are not an array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetParams_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    cJSON* params = cJSON_CreateString("not an array");
    cJSON_AddItemToObject(jsonAbility, "params", params);
    bool result = OHOS::MMI::GetParams(jsonAbility, ability);
    ASSERT_FALSE(result);
    ASSERT_TRUE(ability.params.empty());
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetParams_003
 * @tc.desc: Test Params for nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetParams_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    cJSON* params = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonAbility, "params", params);
    cJSON_AddItemToArray(params, nullptr);
    bool result = OHOS::MMI::GetParams(jsonAbility, ability);
    EXPECT_TRUE(result);
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetParams_004
 * @tc.desc: Test param is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetParams_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    cJSON* params = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonAbility, "params", params);
    bool result = OHOS::MMI::GetParams(jsonAbility, ability);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetParams_005
 * @tc.desc: The test key is not a string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetParams_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    const char* jsonStr = R"({"params":[{"key":123,"value":"value"}]})";
    cJSON* jsonAbility = cJSON_Parse(jsonStr);
    bool result = OHOS::MMI::GetParams(jsonAbility, ability);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetParams_006
 * @tc.desc: The test value is not a string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetParams_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    const char* jsonStr = R"({"params":[{"key":"key","value":123}]})";
    cJSON* jsonAbility = cJSON_Parse(jsonStr);
    bool result = OHOS::MMI::GetParams(jsonAbility, ability);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetParams_007
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetParams_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = cJSON_CreateObject();
    cJSON* params = cJSON_CreateArray();
    cJSON* param1 = cJSON_CreateObject();
    cJSON* key1 = cJSON_CreateString("key");
    cJSON* value1 = cJSON_CreateString("value1");
    cJSON* param2 = cJSON_CreateObject();
    cJSON* key2 = cJSON_CreateString("key");
    cJSON* value2 = cJSON_CreateString("value2");
    cJSON_AddItemToObject(param1, "key", key1);
    cJSON_AddItemToObject(param1, "value", value1);
    cJSON_AddItemToObject(param2, "key", key2);
    cJSON_AddItemToObject(param2, "value", value2);
    cJSON_AddItemToArray(params, param1);
    cJSON_AddItemToArray(params, param2);
    cJSON_AddItemToObject(jsonAbility, "params", params);
    bool result = OHOS::MMI::GetParams(jsonAbility, ability);
    ASSERT_TRUE(result);
    ASSERT_EQ(ability.params.size(), 1);
    ASSERT_EQ(ability.params["key"], "value1");
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ackageAbility_001
 * @tc.desc: Test jsonAbility is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ackageAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    cJSON* jsonAbility = nullptr;
    ASSERT_FALSE(OHOS::MMI::PackageAbility(jsonAbility, ability));
    cJSON_Delete(jsonAbility);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_001
 * @tc.desc: The test case jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = nullptr;
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_002
 * @tc.desc: Test case 2 GetBusinessId failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_003
 * @tc.desc: Test case 3 GetPreKeys failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonData, "businessId", "test");
    ShortcutKey shortcutKey;
    std::vector<std::string> businessIds;
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_004
 * @tc.desc: Test case 4 GetKeyFinalKey failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_004, TestSize.Level1)
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
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_005
 * @tc.desc: Test case 5 GetTrigger failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_005, TestSize.Level1)
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
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_006
 * @tc.desc: Test case 6 GetKeyDownDuration failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_006, TestSize.Level1)
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
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_007
 * @tc.desc: Test case 7 Ability is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_007, TestSize.Level1)
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
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToShortcutKey_008
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToShortcutKey_008, TestSize.Level1)
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
    bool result = OHOS::MMI::ConvertToShortcutKey(jsonData, shortcutKey, businessIds);
    ASSERT_TRUE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyCode_001
 * @tc.desc: The test case jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyCode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = nullptr;
    int32_t keyCodeInt;
    bool result = OHOS::MMI::GetKeyCode(jsonData, keyCodeInt);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyCode_002
 * @tc.desc: Test that the value of the keyCode field is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyCode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"otherKey\": \"value\"}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    int32_t keyCodeInt;
    bool result = OHOS::MMI::GetKeyCode(jsonData, keyCodeInt);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyCode_003
 * @tc.desc: The value of the test keyCode field is negative
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyCode_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"keyCode\": -123}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    int32_t keyCodeInt;
    bool result = OHOS::MMI::GetKeyCode(jsonData, keyCodeInt);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyCode_004
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyCode_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"keyCode\": 123}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    int32_t keyCodeInt;
    bool result = OHOS::MMI::GetKeyCode(jsonData, keyCodeInt);
    EXPECT_TRUE(result);
    EXPECT_EQ(keyCodeInt, 123);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyAction_001
 * @tc.desc: The test case jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const cJSON* jsonData = nullptr;
    int32_t keyActionInt;
    EXPECT_FALSE(OHOS::MMI::GetKeyAction(jsonData, keyActionInt));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyAction_002
 * @tc.desc: The value of the test keyAction field is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyAction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "keyAction", cJSON_CreateString("down"));
    int32_t keyActionInt;
    EXPECT_FALSE(OHOS::MMI::GetKeyAction(jsonData, keyActionInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyAction_003
 * @tc.desc: The value of the Test Caiaction field is 999
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyAction_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyAction", 999);
    int32_t keyActionInt;
    EXPECT_FALSE(OHOS::MMI::GetKeyAction(jsonData, keyActionInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetKeyAction_004
 * @tc.desc: Test for normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetKeyAction_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "keyAction", KeyEvent::KEY_ACTION_DOWN);
    int32_t keyActionInt;
    EXPECT_TRUE(OHOS::MMI::GetKeyAction(jsonData, keyActionInt));
    EXPECT_EQ(keyActionInt, KeyEvent::KEY_ACTION_DOWN);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetDelay_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    int64_t delayInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetDelay(jsonData, delayInt));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetDelay_002
 * @tc.desc: Tests the condition when the delay entry is present but not numeric
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetDelay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "delay", cJSON_CreateString("not a number"));
    int64_t delayInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetDelay(jsonData, delayInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetDelay_003
 * @tc.desc: Tests the case when the delay term is a negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetDelay_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "delay", -1);
    int64_t delayInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetDelay(jsonData, delayInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetDelay_004
 * @tc.desc: Test the condition when all conditions are met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetDelay_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "delay", 10);
    int64_t delayInt = 1;
    EXPECT_TRUE(OHOS::MMI::GetDelay(jsonData, delayInt));
    EXPECT_EQ(delayInt, 10 * SECONDS_SYSTEM);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetRepeatTimes_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetRepeatTimes_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetRepeatTimes(nullptr, repeatTimesInt));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetRepeatTimes_002
 * @tc.desc: Tests the case when the delay term is a negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetRepeatTimes_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "times", cJSON_CreateString("not a number"));
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetRepeatTimes(jsonData, repeatTimesInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetRepeatTimes_003
 * @tc.desc: Test the case when the timers entry is a negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetRepeatTimes_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "times", cJSON_CreateNumber(-1));
    int32_t repeatTimesInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetRepeatTimes(jsonData, repeatTimesInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetRepeatTimes_004
 * @tc.desc: Test the condition when all conditions are met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetRepeatTimes_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "times", cJSON_CreateNumber(1));
    int32_t repeatTimesInt = 1;
    EXPECT_TRUE(OHOS::MMI::GetRepeatTimes(jsonData, repeatTimesInt));
    EXPECT_EQ(repeatTimesInt, 1);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t delay = 1;
    EXPECT_FALSE(OHOS::MMI::GetAbilityStartDelay(nullptr, delay));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_002
 * @tc.desc: Tests the value of the abilityStartDela field is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "abilityStartDelay", cJSON_CreateString("not a number"));
    int64_t delay = 1;
    EXPECT_FALSE(OHOS::MMI::GetAbilityStartDelay(jsonData, delay));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_003
 * @tc.desc: Test the case when the abilityStartDelay entry is a negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "abilityStartDelay", cJSON_CreateNumber(-1));
    int64_t delay = 1;
    EXPECT_FALSE(OHOS::MMI::GetAbilityStartDelay(jsonData, delay));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_004
 * @tc.desc: Test the condition when all conditions are met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "abilityStartDelay", cJSON_CreateNumber(10));
    int64_t delay = 1;
    EXPECT_TRUE(OHOS::MMI::GetAbilityStartDelay(jsonData, delay));
    EXPECT_EQ(delay, 10);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_PackageSequenceKey_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_PackageSequenceKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* json = nullptr;
    SequenceKey sequenceKey;
    bool result = OHOS::MMI::PackageSequenceKey(json, sequenceKey);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_PackageSequenceKey_002
 * @tc.desc: Tests get keyCode failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_PackageSequenceKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"otherKey\": \"value\"}";
    cJSON *json = cJSON_Parse(jsonStr);
    SequenceKey sequenceKey;
    bool result = OHOS::MMI::PackageSequenceKey(json, sequenceKey);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_PackageSequenceKey_003
 * @tc.desc: Tests get keyAction failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_PackageSequenceKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char* jsonStr = "{\"keyCode\": 123}";
    cJSON *jsonData = cJSON_Parse(jsonStr);
    SequenceKey sequenceKey;
    bool result = OHOS::MMI::PackageSequenceKey(jsonData, sequenceKey);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetSequenceKeys_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetSequenceKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    Sequence sequence;
    bool result = OHOS::MMI::GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetSequenceKeys_002
 * @tc.desc: Tests sequenceKeys number must be array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetSequenceKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "sequenceKeys", cJSON_CreateString("invalid"));
    Sequence sequence;
    bool result = OHOS::MMI::GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetSequenceKeys_003
 * @tc.desc: Tests sequenceKeysSize number must less
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetSequenceKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* sequenceKeys = cJSON_CreateArray();
    for (int32_t i = 0; i <= MAX_SEQUENCEKEYS_NUM; ++i) {
        cJSON* sequenceKeyJson = cJSON_CreateObject();
        cJSON_AddItemToObject(sequenceKeyJson, "key", cJSON_CreateString("key"));
        cJSON_AddItemToArray(sequenceKeys, sequenceKeyJson);
    }
    cJSON_AddItemToObject(jsonData, "sequenceKeys", sequenceKeys);
    Sequence sequence;
    bool result = OHOS::MMI::GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetSequenceKeys_004
 * @tc.desc: Tests packege sequenceKey failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetSequenceKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON* sequenceKeys = cJSON_CreateArray();
    for (int32_t i = 0; i < MAX_SEQUENCEKEYS_NUM; ++i) {
        cJSON* sequenceKeyJson = cJSON_CreateObject();
        cJSON_AddItemToObject(sequenceKeyJson, "key", cJSON_CreateString("key"));
        cJSON_AddItemToArray(sequenceKeys, sequenceKeyJson);
    }
    cJSON_AddItemToObject(jsonData, "sequenceKeys", sequenceKeys);
    Sequence sequence;
    bool result = OHOS::MMI::GetSequenceKeys(jsonData, sequence);
    EXPECT_FALSE(result);
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSequenceKeysValid_001
 * @tc.desc: Test case check when sequenceKeys is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSequenceKeysValid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.sequenceKeys = {};
    EXPECT_FALSE(OHOS::MMI::IsSequenceKeysValid(sequence));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSequenceKeysValid_002
 * @tc.desc: Test cases check when the size of sequenceKeys exceeds the maximum limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSequenceKeysValid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.sequenceKeys.resize(MAX_SEQUENCEKEYS_NUM + 1);
    EXPECT_FALSE(OHOS::MMI::IsSequenceKeysValid(sequence));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSequenceKeysValid_003
 * @tc.desc: Test cases check when there are duplicate keys in sequenceKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSequenceKeysValid_003, TestSize.Level1)
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
    EXPECT_FALSE(IsSequenceKeysValid(sequence));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsSequenceKeysValid_004
 * @tc.desc: Test cases check when sequenceKeys are valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsSequenceKeysValid_004, TestSize.Level1)
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
    EXPECT_TRUE(OHOS::MMI::IsSequenceKeysValid(sequence));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToKeySequence_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToKeySequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    Sequence sequence;
    EXPECT_FALSE(OHOS::MMI::ConvertToKeySequence(jsonData, sequence));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ConvertToKeySequence_002
 * @tc.desc: Tests Get sequenceKeys failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ConvertToKeySequence_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    Sequence sequence;
    cJSON_AddItemToObject(jsonData, "sequenceKeys", cJSON_CreateString("invalid"));
    EXPECT_FALSE(OHOS::MMI::ConvertToKeySequence(jsonData, sequence));
    cJSON_Delete(jsonData);
}
} // namespace MMI
} // namespace OHOS