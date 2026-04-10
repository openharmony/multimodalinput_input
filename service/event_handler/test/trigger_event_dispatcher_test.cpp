/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "key_event.h"
#include "key_option.h"
#include "trigger_event_dispatcher.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TriggerEventDispatcherTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class TriggerEventDispatcherTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static inline std::shared_ptr<TriggerEventDispatcher> dispatcher_;
};

void TriggerEventDispatcherTest::SetUpTestCase(void)
{
    dispatcher_ = std::shared_ptr<TriggerEventDispatcher>(TriggerEventDispatcher::GetInstance());
}

void TriggerEventDispatcherTest::TearDownTestCase()
{
    dispatcher_.reset();
}

void TriggerEventDispatcherTest::SetUp()
{
}

void TriggerEventDispatcherTest::TearDown()
{
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_PRESSED_001
 * @tc.desc: Test PRESSED mode should dispatch first down event only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_PRESSED_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_REPEAT_PRESSED_001
 * @tc.desc: Test REPEAT_PRESSED mode should dispatch all down events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_REPEAT_PRESSED_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetTriggerType(REPEAT_PRESSED);
    keyOption->SetFinalKeyDownDuration(0);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_ALL_RELEASED_001
 * @tc.desc: Test ALL_RELEASED mode should dispatch all events including up
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_ALL_RELEASED_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetTriggerType(ALL_RELEASED);
    keyOption->SetFinalKeyDownDuration(0);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldConsume_PRESSED_001
 * @tc.desc: Test PRESSED mode should consume events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldConsume_PRESSED_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetTriggerType(PRESSED);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = dispatcher_->ShouldConsume(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_MatchPreKeys_001
 * @tc.desc: Test preKeys matching with valid preKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_MatchPreKeys_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    std::set<int32_t> preKeys = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT };
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    std::vector<KeyEvent::KeyItem> keyItems;
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    item1.SetPressed(true);
    keyItems.push_back(item1);

    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    item2.SetPressed(true);
    keyItems.push_back(item2);

    KeyEvent::KeyItem item3;
    item3.SetKeyCode(KeyEvent::KEYCODE_A);
    item3.SetPressed(true);
    keyItems.push_back(item3);

    keyEvent->SetKeyItems(keyItems);

    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_CheckDuration_001
 * @tc.desc: Test duration check with zero duration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_CheckDuration_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ClearSubscribeState_001
 * @tc.desc: Test clearing subscribe state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ClearSubscribeState_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);

    std::string subscribeKey = "TestSubscribeKey";
    dispatcher_->ClearSubscribeState(subscribeKey);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);
}
} // namespace MMI
} // namespace OHOS
