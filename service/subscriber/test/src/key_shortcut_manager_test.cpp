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
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
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
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);
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
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
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
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
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
    EXPECT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    KeyShortcutManager::HotKey globalKey {
        .modifiers = { KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT },
        .finalKey = KeyEvent::KEYCODE_M,
    };
    shortcutId = shortcutMgr.RegisterHotKey(globalKey);
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
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
    EXPECT_FALSE(shortcutId >= BASE_SHORTCUT_ID);
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
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey01();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_TRUE(triggered);
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
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey02();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_TRUE(triggered);
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
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey03();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
    bool cvRet = condVar.wait_for(lock, std::chrono::milliseconds(TWICE_LONG_PRESS_TIME),
        [&keyCode]() {
            return (keyCode != KeyEvent::KEYCODE_UNKNOWN);
        });
    EXPECT_TRUE(cvRet);
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_S);
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
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey03();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
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
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey03();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
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
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = TriggerSystemKey06();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_TRUE(triggered);
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
    ASSERT_TRUE(shortcutId >= BASE_SHORTCUT_ID);

    auto keyEvent = ResetAllTriggering();
    ASSERT_TRUE(keyEvent != nullptr);
    EXPECT_TRUE(shortcutMgr.HandleEvent(keyEvent));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
    shortcutMgr.ResetAll();
    std::this_thread::sleep_for(std::chrono::milliseconds(TWICE_LONG_PRESS_TIME));
    EXPECT_EQ(keyCode, KeyEvent::KEYCODE_UNKNOWN);
}
} // namespace MMI
} // namespace OHOS
