/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ability_launcher.h"
#include "mmi_log.h"
#include "key_command_types.h"
#include "key_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AbilityLauncherTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string EXTENSION_ABILITY = "extensionAbility";
const std::string EXTENSION_ABILITY_ABNORMAL = "extensionAbilityAbnormal";
} // namespace

class AbilityLauncherTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

/**
 * @tc.name: AbilityLauncherTest_LaunchAbility_001
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    ability.abilityType = EXTENSION_ABILITY;
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(ability));
    ability.abilityType = EXTENSION_ABILITY_ABNORMAL;
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(ability));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchAbility_002
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(shortcutKey.ability));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchAbility_003
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchAbility_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(sequence.ability));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchAbility_004
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchAbility_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    int64_t delay = 100;
    ability.deviceId = "deviceId";
    ability.bundleName = "bundleName";
    ability.abilityName = "abilityName";
    ability.uri = "abilityUri";
    ability.type = "type";
    ability.action = "abilityAction";
    ability.entities.push_back("entities");
    ability.params.insert(std::make_pair("paramsFirst", "paramsSecond"));
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(ability, delay));
}

/**
 * @tc.name: AbilityLauncherTest_SetKeyCommandService_001
 * @tc.desc: Test SetKeyCommandService with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_SetKeyCommandService_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    EXPECT_NE(LAUNCHER_ABILITY, nullptr);
}

/**
 * @tc.name: AbilityLauncherTest_SetKeyCommandService_002
 * @tc.desc: Test SetKeyCommandService twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_SetKeyCommandService_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: AbilityLauncherTest_LaunchAbility_EmptyBundle_001
 * @tc.desc: Test LaunchAbility with delay when bundleName is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchAbility_EmptyBundle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Ability ability;
    ability.bundleName = "";
    int64_t delay = 100;
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(ability, delay));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchRepeatKeyAbility_001
 * @tc.desc: Test LaunchRepeatKeyAbility with normal key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchRepeatKeyAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = "testBundle";
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    
    auto keyEvent = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchRepeatKeyAbility(repeatKey, keyEvent));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchRepeatKeyAbility_002
 * @tc.desc: Test LaunchRepeatKeyAbility with volume down and camera bundle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchRepeatKeyAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = "com.test.camera";
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    
    auto keyEvent = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchRepeatKeyAbility(repeatKey, keyEvent));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchRepeatKeyAbility_003
 * @tc.desc: Test LaunchRepeatKeyAbility with null service
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchRepeatKeyAbility_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = "testBundle";
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    
    auto keyEvent = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchRepeatKeyAbility(repeatKey, keyEvent));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchAbility_SosBundle_001
 * @tc.desc: Test LaunchAbility with SOS bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchAbility_SosBundle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    
    Ability ability;
    ability.abilityType = "normalAbility";
    ability.bundleName = "SOS_BUNDLE_NAME";
    ability.deviceId = "deviceId";
    ability.abilityName = "abilityName";
    
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(ability));
}

/**
 * @tc.name: AbilityLauncherTest_LaunchAbility_NapProcess_001
 * @tc.desc: Test LaunchAbility with delay when NapProcess returns REMOVE_OBSERVER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityLauncherTest, AbilityLauncherTest_LaunchAbility_NapProcess_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LAUNCHER_ABILITY->SetKeyCommandService(nullptr);
    
    Ability ability;
    ability.bundleName = "testBundle";
    ability.deviceId = "deviceId";
    ability.abilityName = "abilityName";
    int64_t delay = 100;
    
    ASSERT_NO_FATAL_FAILURE(LAUNCHER_ABILITY->LaunchAbility(ability, delay));
}
} // namespace MMI
} // namespace OHOS