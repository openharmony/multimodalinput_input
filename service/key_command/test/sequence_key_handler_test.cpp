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
} // namespace MMI
} // namespace OHOS