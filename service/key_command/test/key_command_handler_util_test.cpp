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
} // namespace MMI
} // namespace OHOS