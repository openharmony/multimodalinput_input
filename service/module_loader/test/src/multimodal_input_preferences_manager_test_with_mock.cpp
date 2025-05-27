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

#include <filesystem>
#include <random>
#include <gtest/gtest.h>

#include "mmi_log.h"
#include "multimodal_input_preferences_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PreferencesManagerTestWithMock"

namespace OHOS {
namespace MMI {
namespace {
constexpr char DATA_ROOT_PATH[] { "/data/service/el1/public/multimodalinput/" };
constexpr char SETTING_FILE_NAME[] { "PreferencesManagerTestWithMock_preferencess.xml" };
}
using namespace testing::ext;

class PreferencesManagerTestWithMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PreferencesManagerTestWithMock::SetUpTestCase()
{}

void PreferencesManagerTestWithMock::TearDownTestCase()
{
    std::filesystem::path testSettingPath { std::string(DATA_ROOT_PATH) + SETTING_FILE_NAME };

    if (std::filesystem::exists(testSettingPath)) {
        std::filesystem::remove(testSettingPath);
    }
}

void PreferencesManagerTestWithMock::SetUp()
{}

void PreferencesManagerTestWithMock::TearDown()
{}

/**
 * @tc.name: PreferencesManagerTestWithMock_InitPreferences_001
 * @tc.desc: Test InitPreferences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_InitPreferences_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(IPreferenceManager::GetInstance()->InitPreferences());
}

/**
 * @tc.name: PreferencesManagerTestWithMock_GetPreferencesSettings_001
 * @tc.desc: Test GetIntValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_GetIntValue_001, TestSize.Level1)
{
    std::string unknownSetting { "unknown-setting" };
    constexpr int32_t defaultValue { 123 };
    ASSERT_NO_FATAL_FAILURE(IPreferenceManager::GetInstance()->GetIntValue(unknownSetting, defaultValue));
    int32_t setting = IPreferenceManager::GetInstance()->GetIntValue(unknownSetting, defaultValue);
    EXPECT_EQ(setting, defaultValue);
}

/**
 * @tc.name: PreferencesManagerTestWithMock_GetIntValue_002
 * @tc.desc: Test GetIntValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_GetIntValue_002, TestSize.Level1)
{
    std::string settingName { "int-setting-01" };
    std::string settingFileName { SETTING_FILE_NAME };
    std::random_device rd;
    std::mt19937 gen(rd());
    int32_t nTests { 4096 };
    double probability { 0.4 };
    std::binomial_distribution<int32_t> distribution(nTests, probability);
    auto settingValue = distribution(gen);
    constexpr int32_t defaultValue { 123 };

    auto ret = IPreferenceManager::GetInstance()->SetIntValue(settingName, settingFileName, settingValue);
    ASSERT_EQ(ret, RET_OK);
    auto setting = IPreferenceManager::GetInstance()->GetIntValue(settingName, defaultValue);
    EXPECT_EQ(setting, settingValue);
}

/**
 * @tc.name: PreferencesManagerTestWithMock_GetPreferencesSettings_001
 * @tc.desc: Test GetBoolValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_GetBoolValue_001, TestSize.Level1)
{
    std::string unknownSetting { "unknown-setting" };
    ASSERT_NO_FATAL_FAILURE(IPreferenceManager::GetInstance()->GetBoolValue(unknownSetting, true));
    bool setting = IPreferenceManager::GetInstance()->GetBoolValue(unknownSetting, true);
    EXPECT_TRUE(setting);
}

/**
 * @tc.name: PreferencesManagerTestWithMock_GetBoolValue_002
 * @tc.desc: Test GetBoolValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_GetBoolValue_002, TestSize.Level1)
{
    std::string settingName { "bool-setting-01" };
    std::string settingFileName { SETTING_FILE_NAME };
    constexpr bool settingValue { true };
    constexpr bool defaultValue { false };
    auto ret = IPreferenceManager::GetInstance()->SetBoolValue(settingName, settingFileName, settingValue);
    ASSERT_EQ(ret, RET_OK);
    auto setting = IPreferenceManager::GetInstance()->GetBoolValue(settingName, defaultValue);
    EXPECT_TRUE(setting);
}

/**
 * @tc.name: PreferencesManagerTestWithMock_GetShortKeyDuration_001
 * @tc.desc: Test GetShortKeyDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_GetShortKeyDuration_001, TestSize.Level1)
{
    std::string testSetting { "unknown-shortkey-setting" };
    ASSERT_NO_FATAL_FAILURE(IPreferenceManager::GetInstance()->GetShortKeyDuration(testSetting));
}

/**
 * @tc.name: PreferencesManagerTestWithMock_GetShortKeyDuration_002
 * @tc.desc: Test GetShortKeyDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_GetShortKeyDuration_002, TestSize.Level1)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    int32_t nTests { 4096 };
    double probability { 0.4 };
    std::binomial_distribution<int32_t> distribution(nTests, probability);
    auto settingValue = distribution(gen);
    std::string testSetting { "unknown-shortkey-setting" };

    auto ret = IPreferenceManager::GetInstance()->SetShortKeyDuration(testSetting, settingValue);
    EXPECT_EQ(ret, RET_OK);
    auto setting = IPreferenceManager::GetInstance()->GetShortKeyDuration(testSetting);
    EXPECT_EQ(setting, settingValue);
}

/**
 * @tc.name: PreferencesManagerTestWithMock_IsInitPreference_001
 * @tc.desc: Test IsInitPreference
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreferencesManagerTestWithMock, PreferencesManagerTestWithMock_IsInitPreference_001, TestSize.Level1)
{
    auto ret = IPreferenceManager::GetInstance()->InitPreferences();
    if (ret != RET_OK) {
        EXPECT_FALSE(IPreferenceManager::GetInstance()->IsInitPreference());
    } else {
        EXPECT_TRUE(IPreferenceManager::GetInstance()->IsInitPreference());
    }
}
} // namespace MMI
} // namespace OHOS
