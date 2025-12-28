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
#include "bundle_name_parser.h"
#include "common_event_support.h"
#include "display_event_monitor.h"
#include "event_log_helper.h"
#include "gesturesense_wrapper.h"
#include "input_event_handler.h"
#include "input_handler_type.h"
#include "input_windows_manager.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_preferences_manager.h"
#include "repeat_key_handler.h"
#include "stylus_key_handler.h"
#include "system_info.h"
#include "test_key_command_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCmdHandleRepeatKeyTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string SOS_BUNDLE_NAME { "com.hmos.emergencycommunication" };
} // namespace
class KeyCmdHandleRepeatKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() override
    {
        shortcutKeys_ = std::make_unique<std::map<std::string, ShortcutKey>>();
        sequences_ = std::make_unique<std::vector<Sequence>>();
        repeatKeys_ = std::make_unique<std::vector<RepeatKey>>();
        excludeKeys_ = std::make_unique<std::vector<ExcludeKey>>();

        context_.shortcutKeys_ = shortcutKeys_.get();
        context_.sequences_ = sequences_.get();
        context_.repeatKeys_ = repeatKeys_.get();
        context_.excludeKeys_ = excludeKeys_.get();

        service_ = std::make_unique<TestKeyCommandService>();
        handler_ = std::make_unique<RepeatKeyHandler>(context_, *service_);
    }

private:
    KeyCommandContext context_;
    std::unique_ptr<std::map<std::string, ShortcutKey>> shortcutKeys_;
    std::unique_ptr<std::vector<Sequence>> sequences_;
    std::unique_ptr<std::vector<RepeatKey>> repeatKeys_;
    std::unique_ptr<std::vector<ExcludeKey>> excludeKeys_;
    std::unique_ptr<TestKeyCommandService> service_;
    std::unique_ptr<RepeatKeyHandler> handler_;
};

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_001
 * @tc.desc: Test if (keyEvent->GetKeyCode() != item.keyCode)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_002
 * @tc.desc: Test if (!isDownStart_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    context_.isDownStart_ = false;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));

    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_003
 * @tc.desc: Test if (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN ||
 * (count_ > maxCount_ && keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_004
 * @tc.desc: Test if (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN ||
 * (count_ > maxCount_ && keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.count_ = 5;
    context_.maxCount_ = 0;
    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_005
 * @tc.desc: Test if (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN ||
 * (count_ > maxCount_ && keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.count_ = 0;
    context_.maxCount_ = 0;
    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_006
 * @tc.desc: Test if (isDownStart_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_007
 * @tc.desc: Test if (it == repeatKeyCountMap_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_008
 * @tc.desc: Test if (it == repeatKeyCountMap_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.ability.bundleName = "bundleName";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_009
 * @tc.desc: Test if (item.ability.bundleName != SOS_BUNDLE_NAME ||
 * downActionTime_ - lastVolumeDownActionTime_ > SOS_INTERVAL_TIMES)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.ability.bundleName = "bundleName";
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_010
 * @tc.desc: Test if (item.ability.bundleName != SOS_BUNDLE_NAME ||
 * downActionTime_ - lastVolumeDownActionTime_ > SOS_INTERVAL_TIMES)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 400000;
    context_.lastVolumeDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_011
 * @tc.desc: Test if (item.ability.bundleName != SOS_BUNDLE_NAME ||
 * downActionTime_ - lastVolumeDownActionTime_ > SOS_INTERVAL_TIMES)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 0;
    context_.lastVolumeDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_012
 * @tc.desc: Test if (repeatKeyCountMap_[item.ability.bundleName] == item.times)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_013
 * @tc.desc: Test if (repeatKeyCountMap_[item.ability.bundleName] == item.times)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_014
 * @tc.desc: Test if (!item.statusConfig.empty())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_015
 * @tc.desc: Test if (!item.statusConfig.empty())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "test";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_016
 * @tc.desc: Test if (ret != RET_OK)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "test";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_017
 * @tc.desc: Test if (ret != RET_OK)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_018
 * @tc.desc: Test if (repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.repeatKeyMaxTimes_.clear();
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_019
 * @tc.desc: Test if (repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 2);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_020
 * @tc.desc: Test if (item.times < repeatKeyMaxTimes_[item.keyCode])
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 2);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_021
 * @tc.desc: Test if (item.times < repeatKeyMaxTimes_[item.keyCode])
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_021, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 0;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 3);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_022
 * @tc.desc: Test if (count_ > item.times && repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end() &&
 * repeatKeyTimerIds_.find(item.ability.bundleName) != repeatKeyTimerIds_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_022, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.count_ = 3;
    context_.maxCount_ = 100;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 3);
    handler_->repeatKeyTimerIds_.emplace(repeatKey.ability.bundleName, 1);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_023
 * @tc.desc: Test if (count_ > item.times && repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end() &&
 * repeatKeyTimerIds_.find(item.ability.bundleName) != repeatKeyTimerIds_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_023, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.count_ = 0;
    context_.maxCount_ = 100;
    context_.repeatKeyMaxTimes_.clear();
    handler_->repeatKeyTimerIds_.clear();
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_024
 * @tc.desc: Test if (count_ > item.times && repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end() &&
 * repeatKeyTimerIds_.find(item.ability.bundleName) != repeatKeyTimerIds_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_024, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.count_ = 3;
    context_.maxCount_ = 100;
    context_.repeatKeyMaxTimes_.clear();
    handler_->repeatKeyTimerIds_.emplace(repeatKey.ability.bundleName, 1);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_025
 * @tc.desc: Test if (count_ > item.times && repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end() &&
 * repeatKeyTimerIds_.find(item.ability.bundleName) != repeatKeyTimerIds_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_025, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.count_ = 3;
    context_.maxCount_ = 100;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 3);
    handler_->repeatKeyTimerIds_.clear();
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_026
 * @tc.desc: Test if (count_ < repeatKeyMaxTimes_[item.keyCode] && repeatKeyTimerIds_[item.ability.bundleName] >= 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_026, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.count_ = 3;
    context_.maxCount_ = 100;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 4);
    handler_->repeatKeyTimerIds_.emplace(repeatKey.ability.bundleName, 1);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_027
 * @tc.desc: Test if (count_ < repeatKeyMaxTimes_[item.keyCode] && repeatKeyTimerIds_[item.ability.bundleName] >= 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_027, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.count_ = 4;
    context_.maxCount_ = 100;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 3);
    handler_->repeatKeyTimerIds_.emplace(repeatKey.ability.bundleName, 1);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCmdHandleRepeatKeyTest_HandleRepeatKey_028
 * @tc.desc: Test if (count_ < repeatKeyMaxTimes_[item.keyCode] && repeatKeyTimerIds_[item.ability.bundleName] >= 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCmdHandleRepeatKeyTest, KeyCmdHandleRepeatKeyTest_HandleRepeatKey_028, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.times = 2;
    repeatKey.delay = 20;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.statusConfig = "POWER_KEY_DOUBLE_CLICK_FOR_WALLET";
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.isDownStart_ = true;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 0;
    context_.count_ = 4;
    context_.maxCount_ = 100;
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 3);
    handler_->repeatKeyTimerIds_.emplace(repeatKey.ability.bundleName, -1);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}
} // namespace MMI
} // namespace OHOS