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
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_005
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = nullptr;
    int64_t abilityStartDelayInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetAbilityStartDelay(jsonData, abilityStartDelayInt));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_006
 * @tc.desc: Tests when delay is not number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "abilityStartDelay", cJSON_CreateString("not a number"));
    int64_t abilityStartDelayInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetAbilityStartDelay(jsonData, abilityStartDelayInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_007
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "abilityStartDelay", -1);
    int64_t abilityStartDelayInt = 1;
    EXPECT_FALSE(OHOS::MMI::GetAbilityStartDelay(jsonData, abilityStartDelayInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_GetAbilityStartDelay_008
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_GetAbilityStartDelay_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, "abilityStartDelay", 1);
    int64_t abilityStartDelayInt = 1;
    EXPECT_TRUE(OHOS::MMI::GetAbilityStartDelay(jsonData, abilityStartDelayInt));
    cJSON_Delete(jsonData);
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ParseMultiFingersTap_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ParseMultiFingersTap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    std::string ability;
    MultiFingersTap mulFingersTap;
    EXPECT_FALSE(OHOS::MMI::ParseMultiFingersTap(parser, ability, mulFingersTap));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_ParseMultiFingersTap_002
 * @tc.desc: Tests when mulFingersTap gesture failed
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_ParseMultiFingersTap_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string ability;
    std::string jsonData = R"({"ability": 1})";
    JsonParser parser(jsonData.c_str());
    MultiFingersTap mulFingersTap;
    EXPECT_FALSE(OHOS::MMI::ParseMultiFingersTap(parser, ability, mulFingersTap));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsParseKnuckleGesture_001
 * @tc.desc: Tests when jsonData is not an object
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsParseKnuckleGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string ability;
    JsonParser parser("");
    KnuckleGesture knuckleGesture;
    EXPECT_FALSE(OHOS::MMI::IsParseKnuckleGesture(parser, ability, knuckleGesture));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsParseKnuckleGesture_002
 * @tc.desc: Tests when knuckle gesture failed
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsParseKnuckleGesture_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string ability;
    std::string jsonData = R"({"ability": 1})";
    JsonParser parser(jsonData.c_str());
    KnuckleGesture knuckleGesture;
    EXPECT_FALSE(OHOS::MMI::IsParseKnuckleGesture(parser, ability, knuckleGesture));
}

/**
 * @tc.name: KeyCommandHandlerUtilTest_IsPackageKnuckleGesture_001
 * @tc.desc: Tests when jsonData is not an number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerUtilTest, KeyCommandHandlerUtilTest_IsPackageKnuckleGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser("");
    std::string knuckleGesture;
    Ability launchAbility;
    EXPECT_FALSE(OHOS::MMI::IsPackageKnuckleGesture(parser.Get(), knuckleGesture, launchAbility));
}
} // namespace MMI
} // namespace OHOS