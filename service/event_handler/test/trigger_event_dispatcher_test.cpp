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

#include <chrono>
#include <thread>
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
    static inline TriggerEventDispatcher* dispatcher_ { nullptr };
};

void TriggerEventDispatcherTest::SetUpTestCase(void)
{
    dispatcher_ = TriggerEventDispatcher::GetInstance();
}

void TriggerEventDispatcherTest::TearDownTestCase()
{
    // Do not delete: GetInstance() returns a static local, not heap-allocated
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
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    // Second dispatch should be blocked (firstDownSent already true)
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);

    // Clean up
    std::string subscribeKey = std::to_string(KeyEvent::KEYCODE_A) + "," +
        std::to_string(PRESSED) + "," + "0";
    dispatcher_->ClearSubscribeState(subscribeKey);
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
    EXPECT_NE(keyEvent, nullptr);
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
    EXPECT_NE(keyEvent, nullptr);
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
    EXPECT_NE(keyEvent, nullptr);
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
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);

    auto keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
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

    keyEvent->SetKeyItem(keyItems);

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
    // Use KEYCODE_B to avoid subscribeKey collision with PRESSED_001 test
    keyOption->SetFinalKey(KeyEvent::KEYCODE_B);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);

    auto keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_B);
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
    // Use KEYCODE_C to avoid collision with other tests
    keyOption->SetFinalKey(KeyEvent::KEYCODE_C);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);

    auto keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    // First dispatch
    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    // Second dispatch should fail (firstDownSent is true)
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);

    // Clear state with the correct subscribeKey matching GenerateSubscribeKey format:
    // preKeys,finalKey,triggerType,duration
    std::string subscribeKey = std::to_string(KeyEvent::KEYCODE_C) + "," +
        std::to_string(PRESSED) + "," + "0";
    dispatcher_->ClearSubscribeState(subscribeKey);

    // After clear, dispatch should succeed again
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_PRESSED_UpReset_001
 * @tc.desc: Test PRESSED finalKey UP resets firstDownSent_ so a later independent DOWN dispatches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_PRESSED_UpReset_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_E);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_E);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(dispatcher_->ShouldDispatch(keyOption, keyEvent));
    EXPECT_FALSE(dispatcher_->ShouldDispatch(keyOption, keyEvent)); // auto-repeat blocked
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_FALSE(dispatcher_->ShouldDispatch(keyOption, keyEvent)); // UP not dispatched, resets state
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(dispatcher_->ShouldDispatch(keyOption, keyEvent)); // independent press dispatches
    std::string subscribeKey = std::to_string(KeyEvent::KEYCODE_E) + "," +
        std::to_string(PRESSED) + "," + "0";
    dispatcher_->ClearSubscribeState(subscribeKey);
}

/**
 * @tc.name: TriggerEventDispatcher_CheckDuration_MillisecondsUnit_001
 * @tc.desc: Regression for StartDurationWindow unit: finalKeyDownDuration is milliseconds,
 *           sleep_for must use std::chrono::milliseconds (was microseconds, 1000x too short).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_CheckDuration_MillisecondsUnit_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_F);
    keyOption->SetTriggerType(REPEAT_PRESSED); // isolate CheckDuration (no firstDownSent_ dedup)
    keyOption->SetFinalKeyDownDuration(100);   // 100ms window after fix; was 100us before fix
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_F);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_FALSE(dispatcher_->ShouldDispatch(keyOption, keyEvent)); // start 100ms window
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // 10ms < 100ms (fixed), >> 100us (buggy)
    EXPECT_FALSE(dispatcher_->ShouldDispatch(keyOption, keyEvent)); // window not yet passed
    std::string subscribeKey = std::to_string(KeyEvent::KEYCODE_F) + "," +
        std::to_string(REPEAT_PRESSED) + "," + "100";
    dispatcher_->ClearSubscribeState(subscribeKey);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_NullOption_001
 * @tc.desc: Test null keyOption returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_NullOption_001, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool result = dispatcher_->ShouldDispatch(nullptr, keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_NullEvent_001
 * @tc.desc: Test null keyEvent returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_NullEvent_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_G);
    keyOption->SetTriggerType(PRESSED);
    bool result = dispatcher_->ShouldDispatch(keyOption, nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldConsume_NullOption_001
 * @tc.desc: Test null keyOption returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldConsume_NullOption_001, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool result = dispatcher_->ShouldConsume(nullptr, keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldConsume_NullEvent_001
 * @tc.desc: Test null keyEvent returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldConsume_NullEvent_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_G);
    keyOption->SetTriggerType(PRESSED);
    bool result = dispatcher_->ShouldConsume(keyOption, nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_PRESSED_WrongKey_001
 * @tc.desc: Test PRESSED mode with a key different from finalKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_PRESSED_WrongKey_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_H);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_I);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_PRESSED_PreKeysMismatch_001
 * @tc.desc: Test PRESSED mode with unmatched preKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_PRESSED_PreKeysMismatch_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys({ KeyEvent::KEYCODE_CTRL_LEFT });
    keyOption->SetFinalKey(KeyEvent::KEYCODE_G);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_G);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldConsume_PRESSED_PreKeyUp_001
 * @tc.desc: Test PRESSED mode consumes preKey up but not preKey down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldConsume_PRESSED_PreKeyUp_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys({ KeyEvent::KEYCODE_CTRL_LEFT });
    keyOption->SetFinalKey(KeyEvent::KEYCODE_J);
    keyOption->SetTriggerType(PRESSED);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool result = dispatcher_->ShouldConsume(keyOption, keyEvent);
    EXPECT_FALSE(result);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    result = dispatcher_->ShouldConsume(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_REPEAT_PRESSED_Up_001
 * @tc.desc: Test REPEAT_PRESSED mode does not dispatch up event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_REPEAT_PRESSED_Up_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_K);
    keyOption->SetTriggerType(REPEAT_PRESSED);
    keyOption->SetFinalKeyDownDuration(0);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_K);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);
    result = dispatcher_->ShouldConsume(keyOption, keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldConsume_ALL_RELEASED_NotActivated_001
 * @tc.desc: Test ALL_RELEASED mode does not consume events before activation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldConsume_ALL_RELEASED_NotActivated_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_L);
    keyOption->SetTriggerType(ALL_RELEASED);
    keyOption->SetFinalKeyDownDuration(0);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_G);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);
    result = dispatcher_->ShouldConsume(keyOption, keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerEventDispatcher_ShouldDispatch_ALL_RELEASED_FullLifecycle_001
 * @tc.desc: Test ALL_RELEASED activation, combo key release and deactivation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ShouldDispatch_ALL_RELEASED_FullLifecycle_001,
    TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys({ KeyEvent::KEYCODE_CTRL_LEFT });
    keyOption->SetFinalKey(KeyEvent::KEYCODE_M);
    keyOption->SetTriggerType(ALL_RELEASED);
    keyOption->SetFinalKeyDownDuration(0);

    std::vector<KeyEvent::KeyItem> keyItems;
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    item.SetPressed(true);
    keyItems.push_back(item);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyItem(keyItems);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_M);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    result = dispatcher_->ShouldConsume(keyOption, keyEvent);
    EXPECT_TRUE(result);
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_M);
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_TRUE(result);

    // After release, a non-combo key must not be dispatched
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_G);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    result = dispatcher_->ShouldDispatch(keyOption, keyEvent);
    EXPECT_FALSE(result);

    dispatcher_->ClearSubscribeState(keyOption);
}

/**
 * @tc.name: TriggerEventDispatcher_ClearSubscribeState_ByKeyOption_001
 * @tc.desc: Test clearing subscribe state via keyOption overload resets first-down flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TriggerEventDispatcherTest, TriggerEventDispatcher_ClearSubscribeState_ByKeyOption_001, TestSize.Level1)
{
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_N);
    keyOption->SetTriggerType(PRESSED);
    keyOption->SetFinalKeyDownDuration(0);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_N);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(dispatcher_->ShouldDispatch(keyOption, keyEvent));
    EXPECT_FALSE(dispatcher_->ShouldDispatch(keyOption, keyEvent));
    dispatcher_->ClearSubscribeState(keyOption);
    EXPECT_TRUE(dispatcher_->ShouldDispatch(keyOption, keyEvent));
}
} // namespace MMI
} // namespace OHOS
