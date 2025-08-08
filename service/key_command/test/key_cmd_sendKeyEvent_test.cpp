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

#include "util.h"

#include "ability_manager_client.h"
#include "common_event_support.h"
#include "bundle_name_parser.h"
#include "display_event_monitor.h"
#include "event_log_helper.h"
#include "gesturesense_wrapper.h"
#include "input_event_handler.h"
#include "input_handler_type.h"
#include "input_windows_manager.h"
#include "key_command_handler.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_preferences_manager.h"
#include "stylus_key_handler.h"
#include "system_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCmdSendKeyEventTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class KeyCmdSendKeyEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_001
 * @tc.desc: Test if (!isHandleSequence_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_002
 * @tc.desc: Test if (!isHandleSequence_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_003
 * @tc.desc: Test if (IsSpecialType(keycode, SpecialType::KEY_DOWN_ACTION))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 0;
    handler.count_ = 1;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_POWER;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_004
 * @tc.desc: Test if (IsSpecialType(keycode, SpecialType::KEY_DOWN_ACTION))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 0;
    handler.count_ = 1;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_CAMERA;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_005
 * @tc.desc: Test if (count_ == repeatKeyMaxTimes_[keycode] - 1 && keycode == KeyEvent::KEYCODE_POWER)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 0;
    handler.count_ = 1;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_POWER;
    handler.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 2);
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_006
 * @tc.desc: Test if (count_ == repeatKeyMaxTimes_[keycode] - 1 && keycode == KeyEvent::KEYCODE_POWER)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 0;
    handler.count_ = 1;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_POWER;
    handler.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 1);
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_007
 * @tc.desc: Test if (i != 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 0;
    handler.count_ = 1;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_POWER;
    handler.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 1);
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCmdSendKeyEventTest_SendKeyEvent_008
 * @tc.desc: Test if (i != 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdSendKeyEventTest, KeyCmdSendKeyEventTest_SendKeyEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 1;
    handler.count_ = 2;
    handler.repeatKey_.keyCode = KeyEvent::KEYCODE_POWER;
    handler.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 1);
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}
} // namespace MMI
} // namespace OHOS