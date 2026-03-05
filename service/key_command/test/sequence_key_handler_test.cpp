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

#include "display_event_monitor.h"
#include "mmi_log.h"
#include "sequence_key_handler.h"
#include "test_key_command_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SequenceKeyHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class SequenceKeyHandlerTest : public testing::Test {
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
        handler_ = std::make_unique<SequenceKeyHandler>(context_, *service_);
    }

private:
    KeyCommandContext context_;
    std::unique_ptr<std::map<std::string, ShortcutKey>> shortcutKeys_;
    std::unique_ptr<std::vector<Sequence>> sequences_;
    std::unique_ptr<std::vector<RepeatKey>> repeatKeys_;
    std::unique_ptr<std::vector<ExcludeKey>> excludeKeys_;
    std::unique_ptr<TestKeyCommandService> service_;
    std::unique_ptr<SequenceKeyHandler> handler_;
};

/**
 * @tc.name: SequenceKeyHandlerTest_RemoveSubscribedTimer
 * @tc.desc: RemoveSubscribedTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_RemoveSubscribedTimer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 16;
    std::list<int32_t> timerIds;
    timerIds.push_back(100);
    context_.specialTimers_.insert(std::make_pair(keyCode, timerIds));
    ASSERT_NO_FATAL_FAILURE(handler_->RemoveSubscribedTimer(keyCode));
    keyCode = 17;
    ASSERT_NO_FATAL_FAILURE(handler_->RemoveSubscribedTimer(keyCode));
}

/**
 * @tc.name: SequenceKeyHandlerTest_InterruptTimers
 * @tc.desc: InterruptTimers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_InterruptTimers, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.timerId = 1;
    handler_->filterSequences_.push_back(sequence);
    ASSERT_NO_FATAL_FAILURE(handler_->InterruptTimers());

    handler_->filterSequences_.clear();
    sequence.timerId = -1;
    handler_->filterSequences_.push_back(sequence);
    ASSERT_NO_FATAL_FAILURE(handler_->InterruptTimers());
}


/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequence
 * @tc.desc: HandleSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequence, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    SequenceKey sequenceKey;
    bool isLaunchAbility = false;
    sequence.statusConfigValue = false;
    ASSERT_FALSE(handler_->HandleSequence(sequence, isLaunchAbility));

    sequence.statusConfigValue = true;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);
    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);

    sequenceKey.keyCode = 2019;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_UP;
    sequence.sequenceKeys.push_back(sequenceKey);
    ASSERT_FALSE(handler_->HandleSequence(sequence, isLaunchAbility));

    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_UP;
    sequence.sequenceKeys.push_back(sequenceKey);
    ASSERT_FALSE(handler_->HandleSequence(sequence, isLaunchAbility));
}

/**
 * @tc.name: SequenceKeyHandlerTest_IsRepeatKeyEvent
 * @tc.desc: IsRepeatKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_IsRepeatKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);

    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_TRUE(handler_->IsRepeatKeyEvent(sequenceKey));

    sequenceKey.keyAction = KeyEvent::KEY_ACTION_UP;
    ASSERT_FALSE(handler_->IsRepeatKeyEvent(sequenceKey));

    handler_->keys_.clear();
    sequenceKey.keyCode = 2019;
    handler_->keys_.push_back(sequenceKey);
    sequenceKey.keyCode = 2020;
    ASSERT_FALSE(handler_->IsRepeatKeyEvent(sequenceKey));
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences
 * @tc.desc: HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler_->matchedSequence_.timerId = 10;
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));
    handler_->matchedSequence_.timerId = -1;
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));

    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(10000);
    SequenceKey sequenceKey;
    Sequence sequence;
    context_.sequences_->push_back(sequence);
    sequenceKey.actionTime = 15000;
    handler_->keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));

    handler_->keys_.clear();
    keyEvent->SetActionTime(1500000);
    sequenceKey.actionTime = 200000;
    sequence.statusConfigValue = false;
    handler_->filterSequences_.push_back(sequence);
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));
}

/**
 * @tc.name: SequenceKeyHandlerTest_AddSequenceKey_001
 * @tc.desc: Test the funcation AddSequenceKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_AddSequenceKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = 3;
    sequenceKey.delay = 4;
    handler_->keys_.push_back(sequenceKey);
    bool ret = handler_->AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_AddSequenceKey_002
 * @tc.desc: Test the funcation AddSequenceKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_AddSequenceKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = 15;
    sequenceKey.delay = 16;
    handler_->keys_.push_back(sequenceKey);
    bool ret = handler_->AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_AddSequenceKey_003
 * @tc.desc: Test the funcation AddSequenceKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_AddSequenceKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = -2;
    sequenceKey.delay = -3;
    handler_->keys_.push_back(sequenceKey);
    bool ret = handler_->AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
    handler_->keys_.clear();
    ret = handler_->AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleNormalSequence_001
 * @tc.desc: Test the funcation HandleNormalSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleNormalSequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    bool isLaunchAbility = true;
    sequence.abilityStartDelay = 0;
    bool ret = handler_->HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    sequence.abilityStartDelay = 1;
    sequence.timerId = -1;
    ret = handler_->HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    sequence.timerId = 1;
    ret = handler_->HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequence_001
 * @tc.desc: Test the funcation HandleSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    SequenceKey sequenceKey;
    bool isLaunchAbility = true;
    sequence.statusConfigValue = false;
    bool ret = handler_->HandleSequence(sequence, isLaunchAbility);
    ASSERT_FALSE(ret);

    sequence.statusConfigValue = true;
    sequenceKey.keyCode = 10;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    sequenceKey.actionTime = 10;
    sequenceKey.delay = 10;
    handler_->keys_.push_back(sequenceKey);
    sequence.sequenceKeys.push_back(sequenceKey);
    ret = handler_->HandleSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences_001
 * @tc.desc: HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler_->matchedSequence_.timerId = 10;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));
    handler_->matchedSequence_.timerId = -1;
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(10000);
    SequenceKey sequenceKey;
    Sequence sequence;
    sequence.statusConfigValue = false;
    sequence.timerId = 1;
    handler_->filterSequences_.push_back(sequence);
    sequenceKey.actionTime = 15000;
    handler_->keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));
    handler_->keys_.clear();
    keyEvent->SetActionTime(1500000);
    sequenceKey.actionTime = 200000;
    sequence.statusConfigValue = false;
    sequence.timerId = 1;
    handler_->filterSequences_.push_back(sequence);
    ASSERT_FALSE(handler_->HandleSequences(keyEvent));
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences_002
 * @tc.desc: HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool ret = handler_->HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences_003
 * @tc.desc: HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler_->sequenceOccurred_ = false;
    handler_->matchedSequence_.timerId = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool ret = handler_->HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleScreenLocked_001
 * @tc.desc: HandleScreenLocked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleScreenLocked_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.timerId = -1;
    bool isLaunchAbility = true;
    bool ret = handler_->HandleScreenLocked(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    sequence.timerId = 2;
    ret = handler_->HandleScreenLocked(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences_004
 * @tc.desc: Test HandleSequences when screen is off and power key is pressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool ret = handler_->HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences_005
 * @tc.desc: Test HandleSequences when active sequence is repeating
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler_->sequenceOccurred_ = true;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);
    bool ret = handler_->HandleSequences(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences_006
 * @tc.desc: Test HandleSequences when sequences configuration is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.sequences_->clear();
    bool ret = handler_->HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequences_007
 * @tc.desc: Test HandleSequences when isLaunchAbility is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequences_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(10000);
    Sequence sequence;
    sequence.statusConfigValue = true;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    sequenceKey.actionTime = 10000;
    sequence.sequenceKeys.push_back(sequenceKey);
    context_.sequences_->push_back(sequence);
    bool ret = handler_->HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_AddSequenceKey_004
 * @tc.desc: Test AddSequenceKey when actionTime is less than last event time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_AddSequenceKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = 100;
    handler_->keys_.push_back(sequenceKey);
    keyEvent->SetKeyCode(2);
    keyEvent->SetKeyAction(2);
    keyEvent->SetActionTime(50);
    bool ret = handler_->AddSequenceKey(keyEvent);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(handler_->keys_.empty());
}

/**
 * @tc.name: SequenceKeyHandlerTest_AddSequenceKey_005
 * @tc.desc: Test AddSequenceKey when delay exceeds MAX_DELAY_TIME
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_AddSequenceKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = 100;
    handler_->keys_.push_back(sequenceKey);
    keyEvent->SetKeyCode(2);
    keyEvent->SetKeyAction(2);
    keyEvent->SetActionTime(10000000);
    bool ret = handler_->AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(handler_->keys_.empty());
}

/**
 * @tc.name: SequenceKeyHandlerTest_AddSequenceKey_006
 * @tc.desc: Test AddSequenceKey when keys size exceeds MAX_SEQUENCEKEYS_NUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_AddSequenceKey_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    for (int i = 0; i < 100; i++) {
        SequenceKey sequenceKey;
        sequenceKey.keyCode = i;
        sequenceKey.keyAction = 2;
        sequenceKey.actionTime = i * 10;
        handler_->keys_.push_back(sequenceKey);
    }
    keyEvent->SetKeyCode(200);
    keyEvent->SetKeyAction(2);
    keyEvent->SetActionTime(1000);
    bool ret = handler_->AddSequenceKey(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequence_002
 * @tc.desc: Test HandleSequence when keysSize > sequenceKeysSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequence_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.statusConfigValue = true;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 10;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);
    handler_->keys_.push_back(sequenceKey);
    bool isLaunchAbility = false;
    bool ret = handler_->HandleSequence(sequence, isLaunchAbility);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequence_003
 * @tc.desc: Test HandleSequence when keyAction not matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequence_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.statusConfigValue = true;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 10;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);
    SequenceKey seqKey;
    seqKey.keyCode = 10;
    seqKey.keyAction = KeyEvent::KEY_ACTION_UP;
    sequence.sequenceKeys.push_back(seqKey);
    bool isLaunchAbility = false;
    bool ret = handler_->HandleSequence(sequence, isLaunchAbility);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleSequence_004
 * @tc.desc: Test HandleSequence when delay not matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleSequence_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.statusConfigValue = true;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 10;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    sequenceKey.actionTime = 100;
    sequenceKey.delay = 100;
    handler_->keys_.push_back(sequenceKey);
    SequenceKey seqKey;
    seqKey.keyCode = 10;
    seqKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    seqKey.actionTime = 100;
    seqKey.delay = 10;
    sequence.sequenceKeys.push_back(seqKey);
    bool isLaunchAbility = false;
    bool ret = handler_->HandleSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleMatchedSequence_001
 * @tc.desc: Test HandleMatchedSequence when screen is off and screenshot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleMatchedSequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.ability.bundleName = "com.test.screenshot";
    bool isLaunchAbility = false;
    bool ret = handler_->HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleMatchedSequence_002
 * @tc.desc: Test HandleMatchedSequence when screen is on and locked with screenshot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleMatchedSequence_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.ability.bundleName = "com.test.screenshot";
    sequence.timerId = -1;
    bool isLaunchAbility = false;
    bool ret = handler_->HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleNormalSequence_002
 * @tc.desc: Test HandleNormalSequence without screenshot permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleNormalSequence_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.ability.bundleName = "com.test.screenshot";
    sequence.abilityStartDelay = 0;
    bool isLaunchAbility = false;
    bool ret = handler_->HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(isLaunchAbility);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleNormalSequence_003
 * @tc.desc: Test HandleNormalSequence without screen record permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleNormalSequence_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.ability.bundleName = "com.test.screenrecorder";
    sequence.abilityStartDelay = 0;
    bool isLaunchAbility = false;
    bool ret = handler_->HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(isLaunchAbility);
}

/**
 * @tc.name: SequenceKeyHandlerTest_HandleScreenLocked_002
 * @tc.desc: Test HandleScreenLocked without screen capture permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_HandleScreenLocked_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Sequence sequence;
    sequence.ability.bundleName = "com.test.screenshot";
    sequence.timerId = -1;
    bool isLaunchAbility = false;
    bool ret = handler_->HandleScreenLocked(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(isLaunchAbility);
}

/**
 * @tc.name: SequenceKeyHandlerTest_IsActiveSequenceRepeating_001
 * @tc.desc: Test IsActiveSequenceRepeating when sequenceOccurred_ is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_IsActiveSequenceRepeating_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler_->sequenceOccurred_ = false;
    bool ret = handler_->IsActiveSequenceRepeating(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_IsActiveSequenceRepeating_002
 * @tc.desc: Test IsActiveSequenceRepeating when keys_ is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_IsActiveSequenceRepeating_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler_->sequenceOccurred_ = true;
    handler_->keys_.clear();
    bool ret = handler_->IsActiveSequenceRepeating(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_IsActiveSequenceRepeating_003
 * @tc.desc: Test IsActiveSequenceRepeating when keyCode not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_IsActiveSequenceRepeating_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(2018);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler_->sequenceOccurred_ = true;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);
    bool ret = handler_->IsActiveSequenceRepeating(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_IsActiveSequenceRepeating_004
 * @tc.desc: Test IsActiveSequenceRepeating when all conditions match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_IsActiveSequenceRepeating_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler_->sequenceOccurred_ = true;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler_->keys_.push_back(sequenceKey);
    bool ret = handler_->IsActiveSequenceRepeating(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SequenceKeyHandlerTest_MarkActiveSequence_001
 * @tc.desc: Test MarkActiveSequence function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_MarkActiveSequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    handler_->sequenceOccurred_ = false;
    handler_->MarkActiveSequence(true);
    ASSERT_TRUE(handler_->sequenceOccurred_);
    handler_->MarkActiveSequence(false);
    ASSERT_FALSE(handler_->sequenceOccurred_);
}

/**
 * @tc.name: SequenceKeyHandlerTest_ResetSequenceKeys_001
 * @tc.desc: Test ResetSequenceKeys function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceKeyHandlerTest, SequenceKeyHandlerTest_ResetSequenceKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    handler_->keys_.push_back(sequenceKey);
    Sequence sequence;
    handler_->filterSequences_.push_back(sequence);
    handler_->ResetSequenceKeys();
    ASSERT_TRUE(handler_->keys_.empty());
    ASSERT_TRUE(handler_->filterSequences_.empty());
}
} // namespace MMI
} // namespace OHOS