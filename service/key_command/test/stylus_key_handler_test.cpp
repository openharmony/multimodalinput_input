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
} // namespace MMI
} // namespace OHOS