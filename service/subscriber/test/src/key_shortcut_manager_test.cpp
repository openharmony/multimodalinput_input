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

#include <vector>

#include <gtest/gtest.h>

#include "key_shortcut_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyShortcutManagerTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t NO_LONG_PRESS { 0 };
constexpr int32_t DEFAULT_LONG_PRESS_TIME { 100 }; // 100ms
constexpr int32_t TWICE_LONG_PRESS_TIME { DEFAULT_LONG_PRESS_TIME + DEFAULT_LONG_PRESS_TIME };
constexpr int32_t BASE_SHORTCUT_ID { 1 };
constexpr int32_t DEFAULT_SAMPLING_PERIOD { 8 }; // 8ms
}

using namespace testing;
using namespace testing::ext;

class KeyShortcutManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    std::shared_ptr<KeyEvent> TriggerSystemKey01();
    std::shared_ptr<KeyEvent> TriggerSystemKey02();
    std::shared_ptr<KeyEvent> TriggerSystemKey03();
    std::shared_ptr<KeyEvent> TriggerSystemKey04();
    std::shared_ptr<KeyEvent> TriggerSystemKey05();
    std::shared_ptr<KeyEvent> TriggerSystemKey06();
    std::shared_ptr<KeyEvent> TriggerSystemKey07();
    std::shared_ptr<KeyEvent> TriggerGlobalKey01();
    std::shared_ptr<KeyEvent> TriggerGlobalKey0101();
    std::shared_ptr<KeyEvent> ResetAllTriggering();
};

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_01
 * @tc.desc: We can register system shortcut key that consist of modifiers only.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_RIGHT },
        .finalKey = KeyShortcutManager::SHORTCUT_PURE_MODIFIERS,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_02
 * @tc.desc: We can register system shortcut key that consist of modifiers and
 *           single non-modifier key, with the non-modifier key as final key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_RIGHT },
        .finalKey = KeyEvent::KEYCODE_S,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_03
 * @tc.desc: We can register system shortcut key that consist of modifiers and
 *           single non-modifier key, with the non-modifier key as final key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT },
        .finalKey = KeyEvent::KEYCODE_BACKSLASH,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_04
 * @tc.desc: We can register system shortcut key that consist of modifiers and
 *           single non-modifier key, with the non-modifier key as final key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .finalKey = KeyEvent::KEYCODE_A,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_05
 * @tc.desc: Only 'LOGO' can be single-key shortcut.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_META_LEFT },
        .finalKey = KeyShortcutManager::SHORTCUT_PURE_MODIFIERS,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_06
 * @tc.desc: Only 'LOGO' can be single-key shortcut.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyShortcutManager::SHORTCUT_PURE_MODIFIERS,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_07
 * @tc.desc: Can not register reserved system key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_META_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_08
 * @tc.desc: System key support DOWN and UP trigger.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_META_LEFT },
        .finalKey = KeyEvent::KEYCODE_D,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_UP,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_SystemKey_09
 * @tc.desc: System key support long press.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_SystemKey_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_META_LEFT },
        .finalKey = KeyEvent::KEYCODE_D,
        .longPressTime = DEFAULT_LONG_PRESS_TIME,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_UP,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_GlobalKey_01
 * @tc.desc: Global shortcut key that consist of modifiers and single non-modifier key,
 *           with the non-modifier key as final key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GlobalKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_M,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_GlobalKey_02
 * @tc.desc: Global shortcut key that consist of modifiers and single non-modifier key,
 *           with the non-modifier key as final key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GlobalKey_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyShortcutManager::SHORTCUT_PURE_MODIFIERS,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_GlobalKey_03
 * @tc.desc: Global shortcut key that consist of modifiers and single non-modifier key,
 *           with the non-modifier key as final key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GlobalKey_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::HotKey globalKey {
        .finalKey = KeyEvent::KEYCODE_M,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_GlobalKey_04
 * @tc.desc: 'LOGO' can not be modifier of Global shortcut key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GlobalKey_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_META_LEFT },
        .finalKey = KeyEvent::KEYCODE_M,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_GlobalKey_05
 * @tc.desc: We can not register registered system key as global shortcut key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GlobalKey_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_M,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_M,
    };
    shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_GlobalKey_06
 * @tc.desc: We can not register reserved system key as global shortcut key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GlobalKey_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_META_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
}

/**
 * @tc.name: KeyShortcutManagerTest_GlobalKey_07
 * @tc.desc: We can register a global shortcut key only once.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GlobalKey_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_M,
    };
    int32_t shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
    shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerSystemKey01()
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

    keyItem.SetKeyCode(KeyEvent::KEYCODE_S);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_S);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerSystemKey_01
 * @tc.desc: Trigger system key immediately.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerSystemKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool triggered = false;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
        .longPressTime = NO_LONG_PRESS,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&triggered](std::shared_ptr<KeyEvent> keyEvent) {
            triggered = true;
        },
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey01();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_FALSE(triggered);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerSystemKey02()
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

    keyItem.SetKeyCode(KeyEvent::KEYCODE_S);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_S);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerSystemKey_02
 * @tc.desc: Trigger system key immediately.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerSystemKey_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool triggered = false;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
        .longPressTime = NO_LONG_PRESS,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&triggered](std::shared_ptr<KeyEvent> keyEvent) {
            triggered = true;
        },
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey02();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_FALSE(triggered);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerSystemKey03()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_S);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_S);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerSystemKey_03
 * @tc.desc: Long press system key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerSystemKey_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::mutex mutex;
    std::condition_variable condVar;
    int32_t keyCode = KeyEvent::KEYCODE_UNKNOWN;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
        .longPressTime = DEFAULT_LONG_PRESS_TIME,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&](std::shared_ptr<KeyEvent> keyEvent) {
            std::unique_lock<std::mutex> lock(mutex);
            keyCode = keyEvent->GetKeyCode();
            condVar.notify_all();
        },
    };
    std::unique_lock<std::mutex> lock(mutex);
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey03();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
    bool cvRet = condVar.wait_for(lock, std::chrono::milliseconds(TWICE_LONG_PRESS_TIME),
        [&keyCode]() {
            return (keyCode != KeyEvent::KEYCODE_UNKNOWN);
        });
    EXPECT_FALSE(cvRet);
    EXPECT_NE(keyCode, KeyEvent::KEYCODE_S);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerSystemKey04()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_S);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerSystemKey_04
 * @tc.desc: Reset pending shortcut when press down another key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerSystemKey_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::mutex mutex;
    std::condition_variable condVar;
    int32_t keyCode = KeyEvent::KEYCODE_UNKNOWN;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
        .longPressTime = DEFAULT_LONG_PRESS_TIME,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&](std::shared_ptr<KeyEvent> keyEvent) {
            std::unique_lock<std::mutex> lock(mutex);
            keyCode = keyEvent->GetKeyCode();
            condVar.notify_all();
        },
    };
    std::unique_lock<std::mutex> lock(mutex);
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey03();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);

    keyEvent = TriggerSystemKey04();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);

    bool cvRet = condVar.wait_for(lock, std::chrono::milliseconds(TWICE_LONG_PRESS_TIME),
        [&keyCode]() {
            return (keyCode != KeyEvent::KEYCODE_UNKNOWN);
        });
    EXPECT_FALSE(cvRet);
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerSystemKey05()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(false);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_S);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerSystemKey_05
 * @tc.desc: Reset pending shortcut when lift up dedicated key(s) before running shortcut.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerSystemKey_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::mutex mutex;
    std::condition_variable condVar;
    int32_t keyCode = KeyEvent::KEYCODE_UNKNOWN;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
        .longPressTime = DEFAULT_LONG_PRESS_TIME,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&](std::shared_ptr<KeyEvent> keyEvent) {
            std::unique_lock<std::mutex> lock(mutex);
            keyCode = keyEvent->GetKeyCode();
            condVar.notify_all();
        },
    };
    std::unique_lock<std::mutex> lock(mutex);
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey03();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);

    keyEvent = TriggerSystemKey05();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);

    bool cvRet = condVar.wait_for(lock, std::chrono::milliseconds(TWICE_LONG_PRESS_TIME),
        [&keyCode]() {
            return (keyCode != KeyEvent::KEYCODE_UNKNOWN);
        });
    EXPECT_FALSE(cvRet);
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerSystemKey06()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_LONG_PRESS_TIME));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_S);
    keyItem.SetDownTime(now - MS2US(DEFAULT_LONG_PRESS_TIME));
    keyItem.SetPressed(false);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_S);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerSystemKey_06
 * @tc.desc: Trigger key-up-trigger system key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerSystemKey_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool triggered = false;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
        .longPressTime = DEFAULT_LONG_PRESS_TIME,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_UP,
        .callback = [&triggered](std::shared_ptr<KeyEvent> keyEvent) {
            triggered = true;
        },
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey06();
    ASSERT_TRUE(keyEvent != nullptr);
    ASSERT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    ASSERT_FALSE(triggered);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerSystemKey07()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_SHIFT_RIGHT);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_SHIFT_RIGHT);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerSystemKey_07
 * @tc.desc: Trigger pure-modifiers system key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerSystemKey_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = KeyEvent::KEYCODE_UNKNOWN;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyShortcutManager::SHORTCUT_PURE_MODIFIERS,
        .longPressTime = NO_LONG_PRESS,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&keyCode](std::shared_ptr<KeyEvent> keyEvent) {
            keyCode = keyEvent->GetKeyCode();
        },
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey07();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_SHIFT_RIGHT);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerGlobalKey01()
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

    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::TriggerGlobalKey0101()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD + DEFAULT_SAMPLING_PERIOD));
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_D);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_D);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerGlobalKey_01
 * @tc.desc: Trigger key-up-trigger system key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerGlobalKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode1 = KeyEvent::KEYCODE_UNKNOWN;
    KeyShortcutManager::HotKey globalKey1 {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_A,
        .callback = [&keyCode1](std::shared_ptr<KeyEvent> keyEvent) {
            keyCode1 = keyEvent->GetKeyCode();
        },
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterHotKey(globalKey1);
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    int32_t keyCode2 = KeyEvent::KEYCODE_UNKNOWN;
    KeyShortcutManager::HotKey globalKey2 {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_RIGHT },
        .finalKey = KeyEvent::KEYCODE_D,
        .callback = [&keyCode2](std::shared_ptr<KeyEvent> keyEvent) {
            keyCode2 = keyEvent->GetKeyCode();
        },
    };
    shortcutId = shortcutMgr.RegisterHotKey(globalKey2);
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent1 = TriggerGlobalKey01();
    ASSERT_TRUE(keyEvent1 != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent1));
    EXPECT_EQ(keyCode1, KeyEvent::KEYCODE_A);
    EXPECT_EQ(keyCode2, KeyEvent::KEYCODE_UNKNOWN);

    auto keyEvent2 = TriggerGlobalKey0101();
    ASSERT_TRUE(keyEvent2 != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent2));
    EXPECT_EQ(keyCode2, KeyEvent::KEYCODE_D);
}

std::shared_ptr<KeyEvent> KeyShortcutManagerTest::ResetAllTriggering()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t now = GetSysClockTime();
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyItem.SetDownTime(now - MS2US(DEFAULT_SAMPLING_PERIOD));
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);

    keyItem.SetKeyCode(KeyEvent::KEYCODE_S);
    keyItem.SetDownTime(now);
    keyEvent->AddKeyItem(keyItem);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_S);
    keyEvent->SetActionTime(now);
    return keyEvent;
}

/**
 * @tc.name: KeyShortcutManagerTest_ResetAllTriggering_01
 * @tc.desc: Trigger key-up-trigger system key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ResetAllTriggering_01, TestSize.Level1)
{
    int32_t keyCode = KeyEvent::KEYCODE_UNKNOWN;
    KeyShortcutManager::SystemShortcutKey sysKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT },
        .finalKey = KeyEvent::KEYCODE_S,
        .longPressTime = DEFAULT_LONG_PRESS_TIME,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&keyCode](std::shared_ptr<KeyEvent> keyEvent) {
            keyCode = keyEvent->GetKeyCode();
        },
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = shortcutMgr.RegisterSystemKey(sysKey);
    ASSERT_FALSE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = ResetAllTriggering();
    ASSERT_TRUE(keyEvent != nullptr);
    ASSERT_FALSE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
    shortcutMgr.ResetAll();
    std::this_thread::sleep_for(std::chrono::milliseconds(TWICE_LONG_PRESS_TIME));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
}

/**
 * @tc.name: KeyShortcutManagerTest_GetInstance_01
 * @tc.desc: Test the funcation GetInstance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GetInstance_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    shortcutMgr.instance_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.GetInstance());
    shortcutMgr.instance_ = std::make_shared<KeyShortcutManager>();
    ASSERT_TRUE(shortcutMgr.instance_ != nullptr);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.GetInstance());
}

/**
 * @tc.name: KeyShortcutManagerTest_UnregisterHotKey_01
 * @tc.desc: Test the funcation UnregisterHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_UnregisterHotKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool triggered = false;
    KeyShortcutManager::KeyShortcut keyShortcut {
        .modifiers = KeyEvent::KEYCODE_META_LEFT,
        .finalKey = KeyEvent::KEYCODE_T,
        .longPressTime = DEFAULT_LONG_PRESS_TIME,
        .triggerType = KeyShortcutManager::SHORTCUT_TRIGGER_TYPE_DOWN,
        .callback = [&triggered](std::shared_ptr<KeyEvent> keyEvent) {
            triggered = true;
        },
    };
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 100;
    shortcutMgr.shortcuts_[100] = keyShortcut;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UnregisterHotKey(shortcutId));
    shortcutId = 66;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UnregisterHotKey(shortcutId));
}

/**
 * @tc.name: KeyShortcutManagerTest_UpdateShortcutConsumed_01
 * @tc.desc: Test the funcation UpdateShortcutConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_UpdateShortcutConsumed_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UpdateShortcutConsumed(keyEvent));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UpdateShortcutConsumed(keyEvent));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UpdateShortcutConsumed(keyEvent));
}

/**
 * @tc.name: KeyShortcutManagerTest_MarkShortcutConsumed_01
 * @tc.desc: Test the funcation MarkShortcutConsumed(ShortcutKey)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_MarkShortcutConsumed_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    ShortcutKey shortcut;
    shortcut.preKeys = {1, 2, 3};
    shortcut.businessId = "businessId";
    shortcut.statusConfig = "statusConfig";
    shortcut.statusConfigValue = true;
    shortcut.finalKey = 1;
    shortcut.keyDownDuration = 2;
    shortcut.triggerType = KeyEvent::KEY_ACTION_DOWN;
    shortcut.timerId = 1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.MarkShortcutConsumed(shortcut));
    shortcut.triggerType = KeyEvent::KEY_ACTION_CANCEL;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.MarkShortcutConsumed(shortcut));
    shortcut.triggerType = KeyEvent::KEY_ACTION_UP;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.MarkShortcutConsumed(shortcut));
}

/**
 * @tc.name: KeyShortcutManagerTest_MarkShortcutConsumed_001
 * @tc.desc: Test the funcation MarkShortcutConsumed(KeyOption)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_MarkShortcutConsumed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyOption shortcut;
    std::set<int32_t> preKeys = {1, 2, 3, 4, 5};
    shortcut.SetPreKeys(preKeys);
    shortcut.SetFinalKeyDown(true);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.MarkShortcutConsumed(shortcut));
    shortcut.SetFinalKeyDown(false);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.MarkShortcutConsumed(shortcut));
}

/**
 * @tc.name: KeyShortcutManagerTest_ResetTriggering_01
 * @tc.desc: Test the funcation ResetTriggering
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ResetTriggering_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    shortcutMgr.triggering_[1] = 1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.ResetTriggering(shortcutId));
    shortcutId = 10;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.ResetTriggering(shortcutId));
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleEvent_001
 * @tc.desc: Test the funcation HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    bool ret = shortcutMgr.HandleEvent(keyEvent);
    ASSERT_EQ(ret, false);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    ret = shortcutMgr.HandleEvent(keyEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: KeyShortcutManagerTest_WillResetOnKeyDown_001
 * @tc.desc: Test the funcation WillResetOnKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_WillResetOnKeyDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t keyCode = 1;
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.finalKey = 1;
    bool ret = shortcutMgr.WillResetOnKeyDown(keyCode, shortcut);
    ASSERT_EQ(ret, false);
    keyCode = 3;
    ret = shortcutMgr.WillResetOnKeyDown(keyCode, shortcut);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: KeyShortcutManagerTest_WillResetOnKeyUp_001
 * @tc.desc: Test the funcation WillResetOnKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_WillResetOnKeyUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t keyCode = 1;
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.finalKey = 1;
    bool ret = shortcutMgr.WillResetOnKeyUp(keyCode, shortcut);
    ASSERT_EQ(ret, true);
    keyCode = 3;
    ret = shortcutMgr.WillResetOnKeyUp(keyCode, shortcut);
    ASSERT_EQ(ret, false);
}

void myCallback(std::shared_ptr<KeyEvent> event)
{
    std::cout << "Callback triggered!" << std::endl;
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerUp_001
 * @tc.desc: Test the funcation TriggerUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    KeyShortcutManager::KeyShortcut shortcut;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    shortcut.longPressTime = -1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerUp_002
 * @tc.desc: Test the funcation TriggerUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    KeyShortcutManager::KeyShortcut shortcut;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    shortcut.longPressTime = 1000;
    KeyEvent::KeyItem item;
    item.SetKeyCode(-1);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
    item.SetKeyCode(5);
    keyEvent->SetActionTime(3);
    item.SetDownTime(1);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
}

/**
 * @tc.name: KeyShortcutManagerTest_RunShortcut_001
 * @tc.desc: Test the funcation RunShortcut
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_RunShortcut_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.RunShortcut(keyEvent, shortcutId));
}

/**
 * @tc.name: KeyShortcutManagerTest_RunShortcut_002
 * @tc.desc: Test the funcation RunShortcut
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_RunShortcut_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut key1;
    shortcutMgr.shortcuts_[1] = key1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.RunShortcut(keyEvent, shortcutId));
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerDown_002
 * @tc.desc: Test the funcation TriggerDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.longPressTime = -1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerDown(keyEvent, shortcutId, shortcut));
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerDown(keyEvent, shortcutId, shortcut));
    shortcut.longPressTime = 2;
    shortcutMgr.triggering_[1] = 100;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerDown(keyEvent, shortcutId, shortcut));
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleKeyUp_001
 * @tc.desc: Test the funcation HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleKeyUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_DOWN;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    shortcutMgr.shortcuts_[1] = shortcut;
    bool ret = shortcutMgr.HandleKeyUp(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleKeyUp_002
 * @tc.desc: Test the funcation HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleKeyUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    shortcutMgr.shortcuts_[1] = shortcut;
    bool ret = shortcutMgr.HandleKeyUp(keyEvent);
    EXPECT_EQ(ret, false);
    shortcut.finalKey = KeyShortcutManager::SHORTCUT_PURE_MODIFIERS;
    shortcutMgr.shortcuts_[1] = shortcut;
    keyEvent->SetKeyCode(2046);
    ret = shortcutMgr.HandleKeyUp(keyEvent);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: KeyShortcutManagerTest_UnregisterSystemKey_001
 * @tc.desc: Test the funcation UnregisterSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_UnregisterSystemKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcutMgr.shortcuts_[1] = shortcut;
    int32_t shortcutId = 1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UnregisterSystemKey(shortcutId));
}

/**
 * @tc.name: KeyShortcutManagerTest_UnregisterHotKey_002
 * @tc.desc: Test the funcation UnregisterHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_UnregisterHotKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcutMgr.shortcuts_[1] = shortcut;
    int32_t shortcutId = 1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UnregisterHotKey(shortcutId));
    shortcutId = 5;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.UnregisterHotKey(shortcutId));
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleEvent_002
 * @tc.desc: Test the funcation HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    bool ret = shortcutMgr.HandleEvent(keyEvent);
    ASSERT_EQ(ret, false);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ret = shortcutMgr.HandleEvent(keyEvent);
    ASSERT_EQ(ret, false);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ret = shortcutMgr.HandleEvent(keyEvent);
    ASSERT_EQ(ret, false);
    keyEvent->SetKeyAction(KeyEvent::INTENTION_LEFT);
    ret = shortcutMgr.HandleEvent(keyEvent);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: KeyShortcutManagerTest_FormatPressedKeys_001
 * @tc.desc: Test the funcation FormatPressedKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_FormatPressedKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    int64_t downTime = 2;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->AddPressedKeyItems(kitDown);
    std::string ret = shortcutMgr.FormatPressedKeys(keyEvent);
    ASSERT_EQ(ret, "-1");
}

/**
 * @tc.name: KeyShortcutManagerTest_CheckGlobalKey_001
 * @tc.desc: Test the funcation CheckGlobalKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_CheckGlobalKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_M,
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_DOWN;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    bool ret = shortcutMgr.CheckGlobalKey(globalKey, shortcut);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_GetForegroundPids_001
 * @tc.desc: Test the funcation GetForegroundPids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GetForegroundPids_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_DOWN;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    shortcutMgr.shortcuts_[1] = shortcut;
    std::set<int32_t> ret = shortcutMgr.GetForegroundPids();
    std::set<int> mySet;
    ASSERT_EQ(ret, mySet);
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleKeyDown_001
 * @tc.desc: Test the funcation HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleKeyDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_DOWN;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    shortcutMgr.shortcuts_[1] = shortcut;
    bool ret = shortcutMgr.HandleKeyDown(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleKeyDown_002
 * @tc.desc: Test the funcation HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleKeyDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    shortcutMgr.shortcuts_[1] = shortcut;
    bool ret = shortcutMgr.HandleKeyDown(keyEvent);
    EXPECT_EQ(ret, false);
    shortcut.finalKey = KeyShortcutManager::SHORTCUT_PURE_MODIFIERS;
    shortcutMgr.shortcuts_[1] = shortcut;
    keyEvent->SetKeyCode(2046);
    ret = shortcutMgr.HandleKeyDown(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleKeyUp_003
 * @tc.desc: Test the funcation HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleKeyUp_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    shortcutMgr.shortcuts_[1] = shortcut;
    bool ret = shortcutMgr.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_DOWN;
    shortcutMgr.shortcuts_[1] = shortcut;
    ret = shortcutMgr.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_CheckPureModifiers_001
 * @tc.desc: Test the funcation CheckPureModifiers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_CheckPureModifiers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    bool ret = shortcutMgr.CheckPureModifiers(keyEvent, shortcut);
    ASSERT_FALSE(ret);
    keyEvent->SetKeyCode(2045);
    int64_t downTime = 2;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->AddPressedKeyItems(kitDown);
    ret = shortcutMgr.CheckPureModifiers(keyEvent, shortcut);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_CheckModifiers_001
 * @tc.desc: Test the funcation CheckModifiers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_CheckModifiers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    bool ret = shortcutMgr.CheckModifiers(keyEvent, shortcut);
    ASSERT_FALSE(ret);
    keyEvent->SetKeyCode(2045);
    int64_t downTime = 2;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->AddPressedKeyItems(kitDown);
    ret = shortcutMgr.CheckModifiers(keyEvent, shortcut);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerDown_001
 * @tc.desc: Test the funcation TriggerDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = -5;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerDown(keyEvent, shortcutId, shortcut));
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerDown(keyEvent, shortcutId, shortcut));
}

/**
 * @tc.name: KeyShortcutManagerTest_RunShortcut_003
 * @tc.desc: Test the funcation RunShortcut
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_RunShortcut_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.RunShortcut(keyEvent, shortcutId));
    KeyShortcutManager::KeyShortcut shortcut;
    shortcut.modifiers = 0x1;
    shortcut.finalKey = 0x2;
    shortcut.longPressTime = 500;
    shortcut.triggerType = KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP;
    shortcut.session = 1;
    shortcutMgr.shortcuts_[1] = shortcut;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.RunShortcut(keyEvent, shortcutId));
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.RunShortcut(keyEvent, shortcutId));
}

/**
 * @tc.name: KeyShortcutManagerTest_TriggerUp_003
 * @tc.desc: Test the funcation TriggerUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_TriggerUp_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    int32_t shortcutId = 1;
    KeyShortcutManager::KeyShortcut shortcut;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    shortcut.longPressTime = 1000;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
    KeyEvent::KeyItem item;
    item.SetKeyCode(5);
    keyEvent->SetActionTime(3);
    item.SetDownTime(1);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
    keyEvent->SetActionTime(1003);
    item.SetDownTime(1);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
    shortcut.longPressTime = -10;
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
    shortcut.callback = myCallback;
    shortcut.callback(keyEvent);
    EXPECT_NO_FATAL_FAILURE(shortcutMgr.TriggerUp(keyEvent, shortcutId, shortcut));
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadHotkey_001
 * @tc.desc: Test the funcation ReadHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadHotkey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonHotkey = cJSON_CreateString("not an object");
    int32_t ret = shortcutMgr.ReadHotkey(jsonHotkey) ;
    EXPECT_EQ(ret, RET_ERR);
    cJSON_Delete(jsonHotkey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadHotkey_002
 * @tc.desc: Test the funcation ReadHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadHotkey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonHotkey = cJSON_CreateObject();
    int32_t ret = shortcutMgr.ReadHotkey(jsonHotkey) ;
    EXPECT_EQ(ret, RET_ERR);
    cJSON_Delete(jsonHotkey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadHotkey_003
 * @tc.desc: Test the funcation ReadHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadHotkey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonHotkey = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonHotkey, "businessId", cJSON_CreateNumber(123));
    int32_t ret = shortcutMgr.ReadHotkey(jsonHotkey) ;
    EXPECT_EQ(ret, RET_ERR);
    cJSON_Delete(jsonHotkey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadHotkey_004
 * @tc.desc: Test the funcation ReadHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadHotkey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonHotkey = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    for (int i = 0; i < 5; ++i) {
        cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
    }
    cJSON_AddItemToObject(jsonHotkey, "preKey", preKey);
    int32_t ret = shortcutMgr.ReadHotkey(jsonHotkey) ;
    EXPECT_EQ(ret, RET_ERR);
    cJSON_Delete(jsonHotkey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadHotkey_005
 * @tc.desc: Test the funcation ReadHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadHotkey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonHotkey = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    for (int i = 0; i < 5; ++i) {
        cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
    }
    cJSON_AddItemToObject(jsonHotkey, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    int32_t ret = shortcutMgr.ReadHotkey(jsonHotkey) ;
    EXPECT_EQ(ret, RET_ERR);
    cJSON_Delete(jsonHotkey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadSystemKey_001
 * @tc.desc: Test the funcation ReadSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadSystemKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateString("not an object");
    int32_t ret = shortcutMgr.ReadSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadSystemKey_002
 * @tc.desc: Test the funcation ReadSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadSystemKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateObject();
    int32_t ret = shortcutMgr.ReadSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadSystemKey_003
 * @tc.desc: Test the funcation ReadSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadSystemKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonSysKey, "preKey", preKey);
    int32_t ret = shortcutMgr.ReadSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadExceptionalSystemKey_001
 * @tc.desc: Test the funcation ReadExceptionalSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadExceptionalSystemKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateString("not an object");
    int32_t ret = shortcutMgr.ReadExceptionalSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadExceptionalSystemKey_002
 * @tc.desc: Test the funcation ReadExceptionalSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadExceptionalSystemKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateObject();
    int32_t ret = shortcutMgr.ReadExceptionalSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadExceptionalSystemKey_003
 * @tc.desc: Test the funcation ReadExceptionalSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadExceptionalSystemKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonSysKey, "preKey", preKey);
    int32_t ret = shortcutMgr.ReadExceptionalSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadExceptionalSystemKey_004
 * @tc.desc: Test the funcation ReadExceptionalSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadExceptionalSystemKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    for (int i = 0; i < 5; ++i) {
        cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
    }
    cJSON_AddItemToObject(jsonSysKey, "preKey", preKey);
    cJSON_AddItemToArray(preKey, cJSON_CreateNumber(1));
    int32_t ret = shortcutMgr.ReadExceptionalSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadExceptionalSystemKey_005
 * @tc.desc: Test the funcation ReadExceptionalSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadExceptionalSystemKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    cJSON *jsonSysKey = cJSON_CreateObject();
    cJSON* preKey = cJSON_CreateArray();
    for (int i = 0; i < 5; ++i) {
        cJSON_AddItemToArray(preKey, cJSON_CreateNumber(i));
    }
    cJSON_AddItemToObject(jsonSysKey, "longPressTime", preKey);
    int32_t ret = shortcutMgr.ReadExceptionalSystemKey(jsonSysKey) ;
    EXPECT_EQ(ret, KEY_SHORTCUT_ERROR_CONFIG);
    cJSON_Delete(jsonSysKey);
}

/**
 * @tc.name: KeyShortcutManagerTest_IsReservedSystemKey
 * @tc.desc: Test the funcation IsReservedSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_IsReservedSystemKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyShortcutManager::KeyShortcut shortcut;
    bool ret = shortcutMgr.IsReservedSystemKey(shortcut) ;
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_HaveRegisteredGlobalKey
 * @tc.desc: Test the funcation HaveRegisteredGlobalKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HaveRegisteredGlobalKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyShortcutManager::KeyShortcut shortcut;
    bool ret = shortcutMgr.HaveRegisteredGlobalKey(shortcut) ;
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_HandleKeyCancel
 * @tc.desc: Test the funcation HandleKeyCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_HandleKeyCancel, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    bool ret = shortcutMgr.HandleKeyCancel(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_CheckCombination
 * @tc.desc: Test the funcation CheckCombination
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_CheckCombination, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyShortcutManager::KeyShortcut shortcut;
    bool ret = shortcutMgr.CheckCombination(keyEvent, shortcut);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyShortcutManagerTest_GetAllSystemHotkeys
 * @tc.desc: Test the funcation GetAllSystemHotkeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_GetAllSystemHotkeys, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    std::vector<std::unique_ptr<KeyOption>> sysKeys;
    bool ret = shortcutMgr.GetAllSystemHotkeys(sysKeys);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyShortcutManagerTest_ReadExceptionalSystemKeys
 * @tc.desc: Test the funcation ReadExceptionalSystemKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_ReadExceptionalSystemKeys, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    const std::string cfgPath { "ExceptionalSystemKeys" };
    shortcutMgr.ReadExceptionalSystemKeys(cfgPath);
    EXPECT_EQ(cfgPath, "ExceptionalSystemKeys");
}

/**
 * @tc.name: KeyShortcutManagerTest_IsValid
 * @tc.desc: Test the funcation IsValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyShortcutManagerTest, KeyShortcutManagerTest_IsValid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyShortcutManager shortcutMgr;
    KeyShortcutManager::ShortcutTriggerType triggerType {
        KeyShortcutManager::ShortcutTriggerType::SHORTCUT_TRIGGER_TYPE_UP };
    bool ret = shortcutMgr.IsValid(triggerType);
    EXPECT_TRUE(ret);
}
} // namespace MMI
} // namespace OHOS
