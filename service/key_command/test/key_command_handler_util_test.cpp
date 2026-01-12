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
} // namespace MMI
} // namespace OHOS