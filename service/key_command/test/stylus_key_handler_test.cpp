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

#include "mmi_log.h"
#include "stylus_key_handler.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StylusKeyHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class StylusKeyHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    std::shared_ptr<KeyEvent> SetupKeyEvent();
};

std::shared_ptr<KeyEvent> StylusKeyHandlerTest::SetupKeyEvent()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_STYLUS_SCREEN);
    return keyEvent;
}

/**
 * @tc.name: StylusKeyHandlerTest_HandleStylusKey_001
 * @tc.desc: Test HandleStylusKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_HandleStylusKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetKeyCode(KeyEvent::UNKNOWN_FUNCTION_KEY);
    STYLUS_HANDLER->isShortHandConfig_ = true;
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_HandleStylusKey_002
 * @tc.desc: Test HandleStylusKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_HandleStylusKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    STYLUS_HANDLER->SetLastEventState(true);
    STYLUS_HANDLER->isShortHandConfig_ = true;
    STYLUS_HANDLER->stylusKey_.statusConfigValue = true;
    STYLUS_HANDLER->IsLaunchAbility();
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_HandleStylusKey_003
 * @tc.desc: Test HandleStylusKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_HandleStylusKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    STYLUS_HANDLER->isShortHandConfig_ = true;
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_IsLaunchAbility_001
 * @tc.desc: Test IsLaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_IsLaunchAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->SetLastEventState(false);
    ASSERT_NO_FATAL_FAILURE(STYLUS_HANDLER->IsLaunchAbility());
}

/**
 * @tc.name: StylusKeyHandlerTest_IsLaunchAbility_002
 * @tc.desc: Test IsLaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_IsLaunchAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->SetLastEventState(true);
    STYLUS_HANDLER->stylusKey_.statusConfigValue = true;
    STYLUS_HANDLER->shortHandTarget_.statusConfigValue = true;
    ASSERT_NO_FATAL_FAILURE(STYLUS_HANDLER->IsLaunchAbility());
}

/**
 * @tc.name: StylusKeyHandlerTest_IsLaunchAbility_003
 * @tc.desc: Test IsLaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_IsLaunchAbility_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->SetLastEventState(true);
    STYLUS_HANDLER->stylusKey_.statusConfigValue = true;
    STYLUS_HANDLER->shortHandTarget_.statusConfigValue = false;
    ASSERT_NO_FATAL_FAILURE(STYLUS_HANDLER->IsLaunchAbility());
}

/**
 * @tc.name: StylusKeyHandlerTest_CreateStatusConfigObserver_001
 * @tc.desc: Test CreateStatusConfigObserver with valid config key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_CreateStatusConfigObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->isShortHandConfig_ = false;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
    ASSERT_TRUE(STYLUS_HANDLER->isShortHandConfig_);
}

/**
 * @tc.name: StylusKeyHandlerTest_CreateStatusConfigObserver_002
 * @tc.desc: Test CreateStatusConfigObserver config value update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_CreateStatusConfigObserver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->isShortHandConfig_ = false;
    STYLUS_HANDLER->stylusKey_.statusConfigValue = false;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
    ASSERT_TRUE(STYLUS_HANDLER->stylusKey_.statusConfigValue == true);
}

/**
 * @tc.name: StylusKeyHandlerTest_CreateStatusConfigObserver_003
 * @tc.desc: Test CreateStatusConfigObserver with shorthand target config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_CreateStatusConfigObserver_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->isShortHandConfig_ = false;
    STYLUS_HANDLER->shortHandTarget_.statusConfigValue = false;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
    ASSERT_TRUE(STYLUS_HANDLER->shortHandTarget_.statusConfigValue == true);
}

/**
 * @tc.name: StylusKeyHandlerTest_CreateStatusConfigObserver_004
 * @tc.desc: Test CreateStatusConfigObserver config already initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_CreateStatusConfigObserver_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->isShortHandConfig_ = true;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
    ASSERT_TRUE(STYLUS_HANDLER->isShortHandConfig_);
}

/**
 * @tc.name: StylusKeyHandlerTest_CreateStatusConfigObserver_005
 * @tc.desc: Test CreateStatusConfigObserver with null keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_CreateStatusConfigObserver_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    STYLUS_HANDLER->isShortHandConfig_ = false;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_HandleStylusKey_KeyCodes_001
 * @tc.desc: Test HandleStylusKey with various keyCodes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_HandleStylusKey_KeyCodes_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    // Test with KEYCODE_STYLUS_SCREEN
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_STYLUS_SCREEN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    STYLUS_HANDLER->isShortHandConfig_ = true;
    STYLUS_HANDLER->SetLastEventState(false);
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);

    // Test with different keyCode
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_STYLUS_FORWARD);
    result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_HandleStylusKey_StateTransition_001
 * @tc.desc: Test HandleStylusKey with state transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_HandleStylusKey_StateTransition_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_STYLUS_SCREEN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    // Test state transition from false to true
    STYLUS_HANDLER->SetLastEventState(false);
    STYLUS_HANDLER->isShortHandConfig_ = true;
    STYLUS_HANDLER->stylusKey_.statusConfigValue = true;
    STYLUS_HANDLER->shortHandTarget_.statusConfigValue = true;
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_TRUE(result);

    // Test state remains true
    STYLUS_HANDLER->SetLastEventState(true);
    result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_HandleStylusKey_StatusConfig_001
 * @tc.desc: Test HandleStylusKey with different statusConfig values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_HandleStylusKey_StatusConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_STYLUS_SCREEN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);

    // Test with statusConfigValue = false for both
    STYLUS_HANDLER->isShortHandConfig_ = true;
    STYLUS_HANDLER->stylusKey_.statusConfigValue = false;
    STYLUS_HANDLER->shortHandTarget_.statusConfigValue = false;
    STYLUS_HANDLER->SetLastEventState(true);
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);

    // Test with mixed statusConfig values
    STYLUS_HANDLER->stylusKey_.statusConfigValue = true;
    STYLUS_HANDLER->shortHandTarget_.statusConfigValue = false;
    result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_SetLastEventState_Edge_001
 * @tc.desc: Test SetLastEventState with edge cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_SetLastEventState_Edge_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Test setting to false multiple times
    STYLUS_HANDLER->SetLastEventState(false);
    STYLUS_HANDLER->SetLastEventState(false);
    ASSERT_NO_FATAL_FAILURE(STYLUS_HANDLER->IsLaunchAbility());

    // Test setting to true multiple times
    STYLUS_HANDLER->SetLastEventState(true);
    STYLUS_HANDLER->SetLastEventState(true);
    ASSERT_NO_FATAL_FAILURE(STYLUS_HANDLER->IsLaunchAbility());

    // Test rapid state changes
    for (int i = 0; i < 10; i++) {
        STYLUS_HANDLER->SetLastEventState(i % 2 == 0);
    }
    ASSERT_NO_FATAL_FAILURE(STYLUS_HANDLER->IsLaunchAbility());
}

/**
 * @tc.name: StylusKeyHandlerTest_NullScenarios_001
 * @tc.desc: Test various null pointer and invalid scenarios
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_NullScenarios_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Test with null keyEvent
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    STYLUS_HANDLER->isShortHandConfig_ = true;
    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);

    // Test with invalid keyEvent attributes
    keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(-1);
    keyEvent->SetKeyAction(-1);
    result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);

    // Test with extreme key code values
    keyEvent->SetKeyCode(INT32_MAX);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: StylusKeyHandlerTest_IsLaunchAbility_MoreStates_001
 * @tc.desc: Test IsLaunchAbility with more state combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_IsLaunchAbility_MoreStates_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Test all combinations of lastEventState and statusConfig values
    for (int lastState = 0; lastState <= 1; lastState++) {
        for (int stylusConfig = 0; stylusConfig <= 1; stylusConfig++) {
            for (int targetConfig = 0; targetConfig <= 1; targetConfig++) {
                STYLUS_HANDLER->SetLastEventState(lastState != 0);
                STYLUS_HANDLER->stylusKey_.statusConfigValue = (stylusConfig != 0);
                STYLUS_HANDLER->shortHandTarget_.statusConfigValue = (targetConfig != 0);
                ASSERT_NO_FATAL_FAILURE(STYLUS_HANDLER->IsLaunchAbility());
            }
        }
    }
}

/**
 * @tc.name: StylusKeyHandlerTest_AbilityLogic_001
 * @tc.desc: Test ability-related logic in StylusKeyHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StylusKeyHandlerTest, StylusKeyHandlerTest_AbilityLogic_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_STYLUS_SCREEN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);

    // Set up ability with various properties
    STYLUS_HANDLER->stylusKey_.ability.bundleName = "test.stylus.bundle";
    STYLUS_HANDLER->stylusKey_.ability.abilityName = "TestAbility";
    STYLUS_HANDLER->stylusKey_.ability.deviceId = "testDevice";

    STYLUS_HANDLER->isShortHandConfig_ = true;
    STYLUS_HANDLER->stylusKey_.statusConfigValue = true;
    STYLUS_HANDLER->SetLastEventState(true);

    auto result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_TRUE(result);

    // Test with empty bundle name
    STYLUS_HANDLER->stylusKey_.ability.bundleName = "";
    result = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    ASSERT_TRUE(result);
}
} // namespace MMI
} // namespace OHOS