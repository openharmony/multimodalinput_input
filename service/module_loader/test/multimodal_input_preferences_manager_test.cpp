/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "multimodal_input_preferences_manager.h"
#include "struct_multimodal.h"
#include "define_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputPreferencesManagerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

const std::string PATH { "/data/service/el1/public/multimodalinput/" };
const std::string TOUCHPAD_FILE_NAME { "touchpad_settings.xml" };
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const std::string strTouchpadRightClickType_ = "rightMenuSwitch";
const std::string strMousePrimaryButton_ = "primaryButton";
constexpr int32_t PRIMARY_BUTTON { 0 };

class MultimodalInputPreferencesManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp();
private:
    std::shared_ptr<MultiModalInputPreferencesManager> manager;
    std::shared_ptr<NativePreferences::Preferences> mousePref;
    std::shared_ptr<NativePreferences::Preferences> touchpadPref;
};

void MultimodalInputPreferencesManagerTest::SetUp()
{
    int32_t errCode = RET_OK;
    manager = std::make_shared<MultiModalInputPreferencesManager>();
    mousePref = NativePreferences::PreferencesHelper::GetPreferences(PATH + MOUSE_FILE_NAME, errCode);
    touchpadPref = NativePreferences::PreferencesHelper::GetPreferences(PATH + TOUCHPAD_FILE_NAME, errCode);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetPreValueTest_001
 * @tc.number: GetPreValueTest_001
 * @tc.desc  : 测试当键在 preferencesMap_ 中找不到时,GetPreValue 应返回 defaultValue
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetPreValueTest_001, TestSize.Level0)
{
    std::string key = "non_existent_key";
    NativePreferences::PreferencesValue defaultValue = std::vector<uint8_t> {1, 1};
    NativePreferences::PreferencesValue result = manager->GetPreValue(key, defaultValue);
    EXPECT_TRUE(result == defaultValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetPreValueTest_002
 * @tc.number: GetPreValueTest_002
 * @tc.desc  : 测试当键在 preferencesMap_ 中找到时,GetPreValue 应返回对应的值
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetPreValueTest_002, TestSize.Level0)
{
    std::string key = "existing_key";
    std::string filePath = "";
    NativePreferences::PreferencesValue defaultValue = std::vector<uint8_t> {1, 1};
    NativePreferences::PreferencesValue expectedValue = std::vector<uint8_t> {2, 2};
    manager->UpdatePreferencesMap(key, TOUCHPAD_FILE_NAME, 2, filePath);
    int ret = manager->SetPreValue(key, filePath, expectedValue);
    ASSERT_TRUE(ret == RET_OK);
    NativePreferences::PreferencesValue result = manager->GetPreValue(key, defaultValue);
    touchpadPref->Delete(key);
    touchpadPref->FlushSync();
    EXPECT_TRUE(result == expectedValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetRightClickTypeValTest_001
 * @tc.number: GetRightClickTypeValTest_001
 * @tc.desc  : 当 touchpadPref 中没有存储 clickType 时,应返回默认的 v2.0 点击类型
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetRightClickTypeValTest_001, TestSize.Level0)
{
    touchpadPref->Delete(strTouchpadRightClickType_);
    touchpadPref->FlushSync();
    int32_t defaultValue = manager->mousePrimaryButton_ == PRIMARY_BUTTON ?
        TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT_BUTTON : TOUCHPAD_TWO_FINGER_TAP_OR_LEFT_BUTTON;
    int32_t result = manager->GetRightClickTypeVal(touchpadPref);
    EXPECT_EQ(result, defaultValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetRightClickTypeValTest_002
 * @tc.number: GetRightClickTypeValTest_002
 * @tc.desc  : 当 touchpadPref 中存储了 clickType 时,应储存新的 [v1, v2] vector
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetRightClickTypeValTest_002, TestSize.Level0)
{
    int32_t valV1 = 2;
    int32_t valV2 = manager->mousePrimaryButton_ == PRIMARY_BUTTON ?
        TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT_BUTTON : TOUCHPAD_TWO_FINGER_TAP_OR_LEFT_BUTTON;
    NativePreferences::PreferencesValue defaultValue = std::vector<uint8_t> {1, 1};
    NativePreferences::PreferencesValue expectedValue = std::vector<uint8_t> {valV1, valV2};
    touchpadPref->Delete(strTouchpadRightClickType_);
    touchpadPref->PutInt(strTouchpadRightClickType_, valV1);
    touchpadPref->FlushSync();
    int32_t result = manager->GetRightClickTypeVal(touchpadPref);
    EXPECT_EQ(result, valV2);
    NativePreferences::PreferencesValue resultPre = touchpadPref->Get(strTouchpadRightClickType_, defaultValue);
    touchpadPref->Delete(strTouchpadRightClickType_);
    touchpadPref->FlushSync();
    EXPECT_TRUE(resultPre == expectedValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetRightClickTypeValTest_003
 * @tc.number: GetRightClickTypeValTest_003
 * @tc.desc  : 当 touchpadPref 中没有存储 clickType 但储存 [v1, v2] vector 时,应返回储存的v2
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetRightClickTypeValTest_003, TestSize.Level0)
{
    int32_t valV1 = 2;
    int32_t valV2 = 2;
    std::string filePath = PATH + TOUCHPAD_FILE_NAME;
    NativePreferences::PreferencesValue defaultValue = std::vector<uint8_t> {1, 1};
    NativePreferences::PreferencesValue expectedValue = std::vector<uint8_t> {valV1, valV2};
    touchpadPref->Delete(strTouchpadRightClickType_);
    touchpadPref->Put(strTouchpadRightClickType_, expectedValue);
    touchpadPref->FlushSync();
    int32_t result = manager->GetRightClickTypeVal(touchpadPref);
    EXPECT_EQ(result, valV2);
    NativePreferences::PreferencesValue resultPre = touchpadPref->Get(strTouchpadRightClickType_, defaultValue);
    touchpadPref->Delete(strTouchpadRightClickType_);
    touchpadPref->FlushSync();
    EXPECT_TRUE(resultPre == expectedValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetPreValueTest_001
 * @tc.number: SetPreValueTest_001
 * @tc.desc  : 测试 SetPreValue 函数在所有操作都成功时返回 RET_OK
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetPreValueTest_001, TestSize.Level0)
{
    std::string filePath = PATH + TOUCHPAD_FILE_NAME;
    std::vector<uint8_t> setVector {1, 1};
    int32_t result = manager->SetPreValue(strTouchpadRightClickType_, filePath, setVector);
    touchpadPref->Delete(strTouchpadRightClickType_);
    touchpadPref->FlushSync();
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_InitPreferencesTest_001
 * @tc.number: InitPreferencesTest_001
 * @tc.desc  : Tests the scenario where the InitPreferences function successfully initializes preferences.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_InitPreferencesTest_001, TestSize.Level0)
{
    int32_t result = manager->InitPreferences();
    EXPECT_EQ(result, RET_OK);
    EXPECT_TRUE(manager->IsInitPreference());
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_IsInitPreferenceTest_001
 * @tc.number: IsInitPreferenceTest_001
 * @tc.desc  : Tests that the IsInitPreference function returns different values before and after initialization.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_IsInitPreferenceTest_001, TestSize.Level0)
{
    // Should be false before initialization
    EXPECT_FALSE(manager->IsInitPreference());
    
    // Should be true after initialization
    manager->InitPreferences();
    EXPECT_TRUE(manager->IsInitPreference());
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetIntValueTest_001
 * @tc.number: GetIntValueTest_001
 * @tc.desc  : Tests that the GetIntValue function
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetIntValueTest_001, TestSize.Level0)
{
    std::string key = "non_existent_key";
    int32_t defaultValue = 100;
    int32_t result = manager->GetIntValue(key, defaultValue);
    EXPECT_EQ(result, defaultValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetIntValueTest_002
 * @tc.number: GetIntValueTest_002
 * @tc.desc  : Tests that the GetIntValue function
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetIntValueTest_002, TestSize.Level0)
{
    std::string key = "test_key";
    int32_t defaultValue = 100;
    int32_t setValue = 200;
    std::string filePath = "";
    manager->UpdatePreferencesMap(key, TOUCHPAD_FILE_NAME, setValue, filePath);
    int32_t result = manager->GetIntValue(key, defaultValue);
    EXPECT_EQ(result, setValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetBoolValueTest_001
 * @tc.number: GetBoolValueTest_001
 * @tc.desc  : Tests that the GetBoolValue function
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetBoolValueTest_001, TestSize.Level0)
{
    std::string key = "non_existent_key";
    bool defaultValue = true;
    bool result = manager->GetBoolValue(key, defaultValue);
    EXPECT_EQ(result, defaultValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetBoolValueTest_002
 * @tc.number: GetBoolValueTest_002
 * @tc.desc  : Tests that the GetBoolValue function
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetBoolValueTest_002, TestSize.Level0)
{
    std::string key = "test_bool_key";
    bool defaultValue = false;
    bool setValue = true;
    std::string filePath = "";
    manager->UpdatePreferencesMap(key, TOUCHPAD_FILE_NAME, static_cast<int32_t>(setValue), filePath);
    bool result = manager->GetBoolValue(key, defaultValue);
    EXPECT_EQ(result, setValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetIntValueTest_001
 * @tc.number: SetIntValueTest_001
 * @tc.desc  : Tests that the SetIntValue function returns RET_OK when successfully setting a value.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetIntValueTest_001, TestSize.Level0)
{
    std::string key = "test_set_int_key";
    std::string filePath = PATH + TOUCHPAD_FILE_NAME;
    int32_t setValue = 50;
    int32_t result = manager->SetIntValue(key, TOUCHPAD_FILE_NAME, setValue);
    touchpadPref->Delete(key);
    touchpadPref->FlushSync();
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetIntValueTest_002
 * @tc.number: SetIntValueTest_002
 * @tc.desc  : Tests that the SetIntValue function returns RET_OK directly when setting the same value.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetIntValueTest_002, TestSize.Level0)
{
    std::string key = "test_set_int_same_key";
    int32_t setValue = 60;
    std::string filePath = "";
    manager->UpdatePreferencesMap(key, TOUCHPAD_FILE_NAME, setValue, filePath);
    // Setting the same value
    int32_t result = manager->SetIntValue(key, TOUCHPAD_FILE_NAME, setValue);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetBoolValueTest_001
 * @tc.number: SetBoolValueTest_001
 * @tc.desc  : Tests that the SetBoolValue function returns RET_OK when successfully setting a value.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetBoolValueTest_001, TestSize.Level0)
{
    std::string key = "test_set_bool_key";
    bool setValue = true;
    int32_t result = manager->SetBoolValue(key, TOUCHPAD_FILE_NAME, setValue);
    touchpadPref->Delete(key);
    touchpadPref->FlushSync();
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetBoolValueTest_002
 * @tc.number: SetBoolValueTest_002
 * @tc.desc  : Tests that the SetBoolValue function returns RET_OK directly when setting the same value.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetBoolValueTest_002, TestSize.Level0)
{
    std::string key = "test_set_bool_same_key";
    bool setValue = false;
    std::string filePath = "";
    manager->UpdatePreferencesMap(key, TOUCHPAD_FILE_NAME, static_cast<int32_t>(setValue), filePath);
    // Setting the same value
    int32_t result = manager->SetBoolValue(key, TOUCHPAD_FILE_NAME, setValue);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetShortKeyDurationTest_001
 * @tc.number: GetShortKeyDurationTest_001
 * @tc.desc  : Tests that the GetShortKeyDuration function
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetShortKeyDurationTest_001, TestSize.Level0)
{
    std::string key = "test_short_key";
    int32_t result = manager->GetShortKeyDuration(key);
    // The second call should retrieve from cache
    int32_t result2 = manager->GetShortKeyDuration(key);
    EXPECT_EQ(result, result2);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetShortKeyDurationTest_002
 * @tc.number: GetShortKeyDurationTest_002
 * @tc.desc  : Tests that the GetShortKeyDuration function returns the default error value when the key does not exist.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetShortKeyDurationTest_002, TestSize.Level0)
{
    std::string key = "non_existent_short_key";
    int32_t result = manager->GetShortKeyDuration(key);
    // Should return ERROR_DELAY_VALUE(-1000) if not found in file
    EXPECT_EQ(result, -1000);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetShortKeyDurationTest_001
 * @tc.number: SetShortKeyDurationTest_001
 * @tc.desc  : Tests that the SetShortKeyDuration function returns RET_OK when successfully setting a value.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetShortKeyDurationTest_001, TestSize.Level0)
{
    std::string key = "test_set_short_key";
    int32_t setValue = 500;
    int32_t result = manager->SetShortKeyDuration(key, setValue);
    // Verify the value in cache
    int32_t getResult = manager->GetShortKeyDuration(key);
    EXPECT_EQ(result, RET_OK);
    EXPECT_EQ(getResult, setValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetShortKeyDurationTest_002
 * @tc.number: SetShortKeyDurationTest_002
 * @tc.desc  : Tests that the SetShortKeyDuration function returns RET_OK directly when setting the same value.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetShortKeyDurationTest_002, TestSize.Level0)
{
    std::string key = "test_set_short_same_key";
    int32_t setValue = 600;
    manager->SetShortKeyDuration(key, setValue);
    // Setting the same value
    // Fixed variable name typo from original code (int32_result -> result)
    int32_t result = manager->SetShortKeyDuration(key, setValue);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_UpdatePreferencesMapTest_001
 * @tc.number: UpdatePreferencesMapTest_001
 * @tc.desc  : Tests that the UpdatePreferencesMap function adds a new entry when the key does not exist.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_UpdatePreferencesMapTest_001, TestSize.Level0)
{
    std::string key = "new_map_key";
    std::string setFile = TOUCHPAD_FILE_NAME;
    int32_t setValue = 77;
    std::string filePath = "";
    manager->UpdatePreferencesMap(key, setFile, setValue, filePath);
    int32_t result = manager->GetIntValue(key, 0);
    EXPECT_EQ(result, setValue);
    EXPECT_TRUE(filePath.find(TOUCHPAD_FILE_NAME) != std::string::npos);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_UpdatePreferencesMapTest_002
 * @tc.number: UpdatePreferencesMapTest_002
 * @tc.desc  : Tests that the UpdatePreferencesMap function updates the value when the key already exists.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_UpdatePreferencesMapTest_002, TestSize.Level0)
{
    std::string key = "update_map_key";
    std::string setFile = TOUCHPAD_FILE_NAME;
    int32_t oldValue = 88;
    int32_t newValue = 99;
    std::string filePath = "";
    manager->UpdatePreferencesMap(key, setFile, oldValue, filePath);
    // Update the value
    manager->UpdatePreferencesMap(key, setFile, newValue, filePath);
    int32_t result = manager->GetIntValue(key, 0);
    EXPECT_EQ(result, newValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_GetPreValueTest_003
 * @tc.number: GetPreValueTest_003
 * @tc.desc  : Tests the GetPreValue function boundary case: empty key string.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_GetPreValueTest_003, TestSize.Level0)
{
    std::string key = "";
    NativePreferences::PreferencesValue defaultValue = std::vector<uint8_t> {0};
    NativePreferences::PreferencesValue result = manager->GetPreValue(key, defaultValue);
    EXPECT_TRUE(result == defaultValue);
}

/**
 * @tc.name  : MultimodalInputPreferencesManagerTest_SetPreValueTest_002
 * @tc.number: SetPreValueTest_002
 * @tc.desc  : Tests the SetPreValue function boundary case: empty vector value.
 */
HWTEST_F(MultimodalInputPreferencesManagerTest,
    MultimodalInputPreferencesManagerTest_SetPreValueTest_002, TestSize.Level0)
{
    std::string filePath = PATH + TOUCHPAD_FILE_NAME;
    std::vector<uint8_t> setVector {};
    int32_t result = manager->SetPreValue("empty_vector_key", filePath, setVector);
    // Empty vector should also be written successfully
    EXPECT_EQ(result, RET_OK);
}
} // namespace MMI
} // namespace OHOS