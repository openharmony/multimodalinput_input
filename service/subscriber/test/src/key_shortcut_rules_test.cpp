/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <condition_variable>
#include <mutex>
#include <vector>

#include <gtest/gtest.h>

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyShortcutRulesTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t NO_LONG_PRESS { 0 };
constexpr int32_t DEFAULT_LONG_PRESS_TIME { 100 }; // 100ms
constexpr int32_t TWICE_LONG_PRESS_TIME { DEFAULT_LONG_PRESS_TIME + DEFAULT_LONG_PRESS_TIME };
constexpr int32_t DEFAULT_SAMPLING_PERIOD { 8 }; // 8ms
}

using namespace testing;
using namespace testing::ext;

class KeyShortcutRulesTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

private:
    std::shared_ptr<KeyEvent> TriggerSystemKey0101();
    std::shared_ptr<KeyEvent> TriggerSystemKey0102();
    std::shared_ptr<KeyEvent> TriggerSystemKey0301();
    std::shared_ptr<KeyEvent> TriggerSystemKey0302();
};

std::shared_ptr<KeyEvent> KeyShortcutRulesTest::TriggerSystemKey0101()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_Q);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_Q);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

std::shared_ptr<KeyEvent> KeyShortcutRulesTest::TriggerSystemKey0102()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_Q);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(false);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_Q);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutRulesTest_TriggerSystemKey_01
 * @tc.desc: If a shortcut was triggered when keys were pressed, shortcut would not be
             checked when lifting up pressed keys.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutRulesTest, KeyShortcutRulesTest_TriggerSystemKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode1 = KeyEvent::KEYCODE_UNKNOWN;
    int32_t keyCode2 = KeyEvent::KEYCODE_UNKNOWN;
    std::mutex mutex;
    std::condition_variable condVar;

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPreKeys(std::set<int32_t> { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT });
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_Q);
    keyOption1->SetFinalKeyDown(true);
    keyOption1->SetFinalKeyDownDuration(NO_LONG_PRESS);

    auto subscribe1 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption1,
        [&](std::shared_ptr<KeyEvent> keyEvent) {
            std::unique_lock<std::mutex> guard { mutex };
            keyCode1 = keyEvent->GetKeyCode();
            condVar.notify_all();
        });
    EXPECT_TRUE(subscribe1 >= 0);

    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPreKeys(std::set<int32_t> { KeyEvent::KEYCODE_SHIFT_LEFT });
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_Q);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(NO_LONG_PRESS);

    auto subscribe2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [&](std::shared_ptr<KeyEvent> keyEvent) {
            std::unique_lock<std::mutex> guard { mutex };
            keyCode2 = keyEvent->GetKeyCode();
            condVar.notify_all();
        });
    EXPECT_TRUE(subscribe2 >= 0);

    std::unique_lock<std::mutex> guard { mutex };
    auto keyEvent1 = TriggerSystemKey0101();
    ASSERT_TRUE(keyEvent1 != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent1);

    EXPECT_TRUE(condVar.wait_for(guard, std::chrono::milliseconds(DEFAULT_LONG_PRESS_TIME),
        [&keyCode1]() {
            return (keyCode1 != KeyEvent::KEYCODE_UNKNOWN);
        }));
    EXPECT_EQ(keyCode1, KeyEvent::KEYCODE_Q);

    auto keyEvent2 = TriggerSystemKey0102();
    ASSERT_TRUE(keyEvent2 != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent2);

    EXPECT_FALSE(condVar.wait_for(guard, std::chrono::milliseconds(DEFAULT_LONG_PRESS_TIME),
        [&keyCode2]() {
            return (keyCode2 != KeyEvent::KEYCODE_UNKNOWN);
        }));
    EXPECT_EQ(keyCode2, KeyEvent::KEYCODE_UNKNOWN);

    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribe1);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribe2);
}

/**
 * @tc.name: KeyShortcutRulesTest_TriggerSystemKey_02
 * @tc.desc: If a shortcut was triggered when keys were pressed, shortcut would not be
             checked when lifting up pressed keys.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutRulesTest, KeyShortcutRulesTest_TriggerSystemKey_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode1 = KeyEvent::KEYCODE_UNKNOWN;
    int32_t keyCode2 = KeyEvent::KEYCODE_UNKNOWN;
    std::mutex mutex;
    std::condition_variable condVar;

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPreKeys(std::set<int32_t> { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT });
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_Q);
    keyOption1->SetFinalKeyDown(true);
    keyOption1->SetFinalKeyDownDuration(NO_LONG_PRESS);

    auto subscribe1 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption1,
        [&](std::shared_ptr<KeyEvent> keyEvent) {
            std::unique_lock<std::mutex> guard { mutex };
            keyCode1 = keyEvent->GetKeyCode();
            condVar.notify_all();
        });
    EXPECT_TRUE(subscribe1 >= 0);

    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPreKeys(std::set<int32_t> { KeyEvent::KEYCODE_SHIFT_LEFT });
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_Q);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(NO_LONG_PRESS);

    auto subscribe2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [&](std::shared_ptr<KeyEvent> keyEvent) {
            std::unique_lock<std::mutex> guard { mutex };
            keyCode2 = keyEvent->GetKeyCode();
            condVar.notify_all();
        });
    EXPECT_TRUE(subscribe2 >= 0);

    std::unique_lock<std::mutex> guard { mutex };
    auto keyEvent2 = TriggerSystemKey0102();
    ASSERT_TRUE(keyEvent2 != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent2);

    EXPECT_TRUE(condVar.wait_for(guard, std::chrono::milliseconds(DEFAULT_LONG_PRESS_TIME),
        [&keyCode2]() {
            return (keyCode2 != KeyEvent::KEYCODE_UNKNOWN);
        }));
    EXPECT_EQ(keyCode2, KeyEvent::KEYCODE_Q);

    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribe1);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribe2);
}

std::shared_ptr<KeyEvent> KeyShortcutRulesTest::TriggerSystemKey0301()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_Q);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_Q);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

std::shared_ptr<KeyEvent> KeyShortcutRulesTest::TriggerSystemKey0302()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_Q);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_Q);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutRulesTest_TriggerSystemKey_03
 * @tc.desc: If a shortcut was triggered when keys were pressed, shortcut would not be
             checked when lifting up pressed keys.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutRulesTest, KeyShortcutRulesTest_TriggerSystemKey_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode1 = KeyEvent::KEYCODE_UNKNOWN;
    int32_t keyCode2 = KeyEvent::KEYCODE_UNKNOWN;

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPreKeys(std::set<int32_t> { KeyEvent::KEYCODE_SHIFT_LEFT });
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_Q);
    keyOption1->SetFinalKeyDown(true);
    keyOption1->SetFinalKeyDownDuration(DEFAULT_LONG_PRESS_TIME);

    auto subscribe1 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption1,
        [&](std::shared_ptr<KeyEvent> keyEvent) {
            keyCode1 = keyEvent->GetKeyCode();
        });
    EXPECT_TRUE(subscribe1 >= 0);

    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPreKeys(std::set<int32_t> { KeyEvent::KEYCODE_SHIFT_LEFT });
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_Q);
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKeyDownDuration(NO_LONG_PRESS);

    auto subscribe2 = InputManager::GetInstance()->SubscribeKeyEvent(keyOption2,
        [&](std::shared_ptr<KeyEvent> keyEvent) {
            keyCode2 = keyEvent->GetKeyCode();
        });
    EXPECT_TRUE(subscribe2 >= 0);

    auto keyEvent1 = TriggerSystemKey0301();
    ASSERT_TRUE(keyEvent1 != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent1);

    auto keyEvent2 = TriggerSystemKey0302();
    ASSERT_TRUE(keyEvent2 != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent2);

    std::this_thread::sleep_for(std::chrono::milliseconds(TWICE_LONG_PRESS_TIME));
    EXPECT_EQ(keyCode1, KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_EQ(keyCode2, KeyEvent::KEYCODE_Q);

    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribe1);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribe2);
}
} // namespace MMI
} // namespace OHOS
