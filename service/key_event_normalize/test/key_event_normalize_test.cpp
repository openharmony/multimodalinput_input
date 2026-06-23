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

#include <cstdio>

#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "general_keyboard.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"
#include "key_event_normalize.h"
#include "libinput_wrapper.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventNormalizeTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class KeyEventNormalizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(){};
    void TearDown(){};

private:
    static void SetupKeyboard();
    static void CloseKeyboard();
    static GeneralKeyboard vKeyboard_;
    static LibinputWrapper libinput_;
};

GeneralKeyboard KeyEventNormalizeTest::vKeyboard_;
LibinputWrapper KeyEventNormalizeTest::libinput_;

void KeyEventNormalizeTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupKeyboard();
}

void KeyEventNormalizeTest::TearDownTestCase(void)
{
    CloseKeyboard();
}

void KeyEventNormalizeTest::SetupKeyboard()
{
    if (!vKeyboard_.SetUp()) {
        GTEST_SKIP();
    }
    std::cout << "device node name: " << vKeyboard_.GetDevPath() << std::endl;
    if (!libinput_.AddPath(vKeyboard_.GetDevPath())) {
        GTEST_SKIP();
    }
    libinput_event *event = libinput_.Dispatch();
    if (!event) {
        GTEST_SKIP();
    }
    if (libinput_event_get_type(event) != LIBINPUT_EVENT_DEVICE_ADDED) {
        GTEST_SKIP();
    }
    struct libinput_device *device = libinput_event_get_device(event);
    if (!device) {
        GTEST_SKIP();
    }
    INPUT_DEV_MGR->OnInputDeviceAdded(device);
}

void KeyEventNormalizeTest::CloseKeyboard()
{
    libinput_.RemovePath(vKeyboard_.GetDevPath());
    vKeyboard_.Close();
}

/**
 * @tc.name: KeyEventNormalizeTest_Normalize_001
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_Normalize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "keyboard device: " << libinput_device_get_name(dev) << std::endl;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    int32_t result = KeyEventHdr->Normalize(event, keyEvent);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest_Normalize_002
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_Normalize_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "keyboard device: " << libinput_device_get_name(dev) << std::endl;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<int32_t> pressedKeys {};
    pointerEvent->SetPressedKeys(pressedKeys);
    int32_t result = KeyEventHdr->Normalize(event, keyEvent);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest_Normalize_003
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_Normalize_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "keyboard device: " << libinput_device_get_name(dev) << std::endl;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<int32_t> pressedKeys { KeyEvent::KEYCODE_CTRL_LEFT };
    pointerEvent->SetPressedKeys(pressedKeys);
    int32_t result = KeyEventHdr->Normalize(event, keyEvent);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleKeyAction_001
 * @tc.desc: Test HandleKeyAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleKeyAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "keyboard device: " << libinput_device_get_name(dev) << std::endl;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem item;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleKeyAction(dev, item, keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleKeyAction_002
 * @tc.desc: Test HandleKeyAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleKeyAction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "keyboard device: " << libinput_device_get_name(dev) << std::endl;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item;
    item.SetKeyCode(1);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(1);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleKeyAction(dev, item, keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleKeyAction_003
 * @tc.desc: Test HandleKeyAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleKeyAction_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "keyboard device: " << libinput_device_get_name(dev) << std::endl;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item;
    item.SetKeyCode(1);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(3);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleKeyAction(dev, item, keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_SetShieldStatus_001
 * @tc.desc: Test SetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SetShieldStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t shieldMode = -1;
    bool isShield = true;
    int32_t ret = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    ASSERT_EQ(ret, RET_ERR);
    shieldMode = 2;
    isShield = true;
    ret = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest_SetShieldStatus_002
 * @tc.desc: Test SetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SetShieldStatus_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t shieldMode = 2;
    bool isShield = false;
    int32_t ret = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    ASSERT_EQ(ret, RET_ERR);
    shieldMode = -1;
    isShield = false;
    ret = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test shieldMode_Equal_lastShieldMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, shieldMode_Equal_lastShieldMode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = true;
    int32_t shieldMode = -1;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test shieldMode_NotEqual_lastShieldMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, shieldMode_NotEqual_lastShieldMode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = false;
    int32_t shieldMode = 3;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test SetShieldStatus_FACTORY_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, SetShieldStatus_FACTORY_MODE, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = false;
    int32_t shieldMode = 0;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test SetShieldStatus_OOBE_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, SetShieldStatus_OOBE_MODE, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = false;
    int32_t shieldMode = 1;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test SetShieldStatus_NotFound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, SetShieldStatus_NotFound, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = false;
    int32_t shieldMode = -1;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test GetShieldStatus_FACTORY_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, GetShieldStatus_FACTORY_MODE, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = false;
    int32_t shieldMode = 0;
    int32_t result = KeyEventHdr->GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test GetShieldStatus_OOBE_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, GetShieldStatus_OOBE_MODE, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = false;
    int32_t shieldMode = 1;
    int32_t result = KeyEventHdr->GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test GetShieldStatus_NotFound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, GetShieldStatus_NotFound, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isShield = false;
    int32_t shieldMode = -1;
    int32_t result = KeyEventHdr->GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest_GetKeyEvent_001
 * @tc.desc: Test GetKeyEvent returns non-null KeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_GetKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEventHdr->GetKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
}

/**
 * @tc.name: KeyEventNormalizeTest_SetGetCurrentShieldMode_001
 * @tc.desc: Test SetCurrentShieldMode and GetCurrentShieldMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SetGetCurrentShieldMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t defaultMode = KeyEventHdr->GetCurrentShieldMode();
    KeyEventHdr->SetCurrentShieldMode(SHIELD_MODE::FACTORY_MODE);
    EXPECT_EQ(KeyEventHdr->GetCurrentShieldMode(), SHIELD_MODE::FACTORY_MODE);
    KeyEventHdr->SetCurrentShieldMode(SHIELD_MODE::OOBE_MODE);
    EXPECT_EQ(KeyEventHdr->GetCurrentShieldMode(), SHIELD_MODE::OOBE_MODE);
    KeyEventHdr->SetCurrentShieldMode(defaultMode);
    EXPECT_EQ(KeyEventHdr->GetCurrentShieldMode(), defaultMode);
}

/**
 * @tc.name: KeyEventNormalizeTest_IsScreenFold_001
 * @tc.desc: Test IsScreenFold returns false when Init not called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_IsScreenFold_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(KeyEventHdr->IsScreenFold());
}

/**
 * @tc.name: KeyEventNormalizeTest_ShieldStatusChain_001
 * @tc.desc: Test ShieldStatus set true and verify with GetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_ShieldStatusChain_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = KeyEventHdr->SetShieldStatus(SHIELD_MODE::FACTORY_MODE, true);
    ASSERT_EQ(ret, RET_OK);
    bool isShield = false;
    ret = KeyEventHdr->GetShieldStatus(SHIELD_MODE::FACTORY_MODE, isShield);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(isShield);
    ret = KeyEventHdr->SetShieldStatus(SHIELD_MODE::FACTORY_MODE, false);
    ASSERT_EQ(ret, RET_OK);
    isShield = true;
    ret = KeyEventHdr->GetShieldStatus(SHIELD_MODE::FACTORY_MODE, isShield);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_FALSE(isShield);
    KeyEventHdr->SetCurrentShieldMode(SHIELD_MODE::UNSET_MODE);
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleKeyAction_NullDevice
 * @tc.desc: Verify HandleKeyAction with nullptr device does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleKeyAction_NullDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEvent::KeyItem item;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleKeyAction(nullptr, item, keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleKeyAction_NullKeyEvent
 * @tc.desc: Verify HandleKeyAction with nullptr keyEvent does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleKeyAction_NullKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    KeyEvent::KeyItem item;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleKeyAction(dev, item, nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_SetKeyStatusRecord_001
 * @tc.desc: Verify SetKeyStatusRecord sets enable and timeout without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SetKeyStatusRecord_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SetKeyStatusRecord(true, 5000));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SetKeyStatusRecord(false, 0));
}

/**
 * @tc.name: KeyEventNormalizeTest_KeyEventAutoUp_Nullptr
 * @tc.desc: Verify KeyEventAutoUp with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_KeyEventAutoUp_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->KeyEventAutoUp(nullptr, 1000));
}

/**
 * @tc.name: KeyEventNormalizeTest_KeyEventAutoUp_InvalidTimeout
 * @tc.desc: Verify KeyEventAutoUp with timeout <= 0 does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_KeyEventAutoUp_InvalidTimeout, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->KeyEventAutoUp(keyEvent, 0));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->KeyEventAutoUp(keyEvent, -1));
}

/**
 * @tc.name: KeyEventNormalizeTest_SyncLedStateFromKeyEvent_Nullptr
 * @tc.desc: Verify SyncLedStateFromKeyEvent with nullptr device does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SyncLedStateFromKeyEvent_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(KeyEventHdr->SyncLedStateFromKeyEvent(nullptr), RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest_InterruptAutoRepeatKeyEvent_Nullptr
 * @tc.desc: Verify InterruptAutoRepeatKeyEvent with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_InterruptAutoRepeatKeyEvent_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->InterruptAutoRepeatKeyEvent(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleSimulatedModifierKeyActionFromShell_Nullptr
 * @tc.desc: Verify HandleSimulatedModifierKeyActionFromShell with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleSimulatedModifierKeyActionFromShell_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleSimulatedModifierKeyActionFromShell(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_UpdateSimulatedEventModifierState_Nullptr
 * @tc.desc: Verify UpdateSimulatedEventModifierState with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_UpdateSimulatedEventModifierState_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->UpdateSimulatedEventModifierState(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_CheckSimulatedModifierKeyEvent_Nullptr
 * @tc.desc: Verify CheckSimulatedModifierKeyEvent with nullptr returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_CheckSimulatedModifierKeyEvent_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(KeyEventHdr->CheckSimulatedModifierKeyEvent(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_CheckSimulatedModifierKeyEvent_NotSimulated
 * @tc.desc: Verify CheckSimulatedModifierKeyEvent returns false for non-simulated event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_CheckSimulatedModifierKeyEvent_NotSimulated, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_FALSE(KeyEventHdr->CheckSimulatedModifierKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_CheckSimulatedModifierKeyEventFromShell_Nullptr
 * @tc.desc: Verify CheckSimulatedModifierKeyEventFromShell with nullptr returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_CheckSimulatedModifierKeyEventFromShell_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(KeyEventHdr->CheckSimulatedModifierKeyEventFromShell(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_SimulatedModifierKeyEventNormalize_Nullptr
 * @tc.desc: Verify SimulatedModifierKeyEventNormalize with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SimulatedModifierKeyEventNormalize_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SimulatedModifierKeyEventNormalize(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleSimulatedModifierKeyAction_Nullptr
 * @tc.desc: Verify HandleSimulatedModifierKeyAction with nullptr keyEvent does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleSimulatedModifierKeyAction_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleSimulatedModifierKeyAction(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_SyncSwitchFunctionKeyState_Nullptr
 * @tc.desc: Verify SyncSwitchFunctionKeyState with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SyncSwitchFunctionKeyState_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SyncSwitchFunctionKeyState(nullptr, KeyEvent::KEYCODE_CAPS_LOCK));
}

/**
 * @tc.name: KeyEventNormalizeTest_SyncSimulatedModifierKeyEventState_Nullptr
 * @tc.desc: Verify SyncSimulatedModifierKeyEventState with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SyncSimulatedModifierKeyEventState_Nullptr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SyncSimulatedModifierKeyEventState(nullptr));
}

/**
 * @tc.name: KeyEventNormalizeTest_UpdateKeyState_Down
 * @tc.desc: Verify UpdateKeyState with KEY_ACTION_DOWN inserts rawCode without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_UpdateKeyState_Down, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetDeviceId(9999);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->UpdateKeyState(42, *keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_UpdateKeyState_Up
 * @tc.desc: Verify UpdateKeyState with KEY_ACTION_UP erases rawCode without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_UpdateKeyState_Up, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEventDown = KeyEvent::Create();
    ASSERT_NE(keyEventDown, nullptr);
    keyEventDown->SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyEventDown->SetDeviceId(9998);
    KeyEventHdr->UpdateKeyState(99, *keyEventDown);
    auto keyEventUp = KeyEvent::Create();
    ASSERT_NE(keyEventUp, nullptr);
    keyEventUp->SetAction(KeyEvent::KEY_ACTION_UP);
    keyEventUp->SetDeviceId(9998);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->UpdateKeyState(99, *keyEventUp));
}

/**
 * @tc.name: KeyEventNormalizeTest_InterruptAutoRepeatKeyEvent_DownInterrupt
 * @tc.desc: Verify InterruptAutoRepeatKeyEvent when keyAction is DOWN and different from repeat key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_InterruptAutoRepeatKeyEvent_DownInterrupt, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->InterruptAutoRepeatKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_InterruptAutoRepeatKeyEvent_UpInterrupt
 * @tc.desc: Verify InterruptAutoRepeatKeyEvent when keyAction is UP and same as repeat key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_InterruptAutoRepeatKeyEvent_UpInterrupt, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->InterruptAutoRepeatKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyEventNormalizeTest_CheckKeyEventAutoUpTimer_NotFound
 * @tc.desc: Verify CheckKeyEventAutoUpTimer returns false for keyCode not in map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_CheckKeyEventAutoUpTimer_NotFound, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(KeyEventHdr->CheckKeyEventAutoUpTimer(KeyEvent::KEYCODE_UNKNOWN));
}

/**
 * @tc.name: KeyEventNormalizeTest_HandleSimulatedModifierKeyDown_Up_Normal
 * @tc.desc: Verify HandleSimulatedModifierKeyDown and HandleSimulatedModifierKeyUp with valid keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_HandleSimulatedModifierKeyDown_Up_Normal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleSimulatedModifierKeyDown(keyEvent, item));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->HandleSimulatedModifierKeyUp(keyEvent, item));
}

/**
 * @tc.name: KeyEventNormalizeTest_SyncSwitchFunctionKeyState_UnknownFunctionKey
 * @tc.desc: Verify SyncSwitchFunctionKeyState with non-function key code does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_SyncSwitchFunctionKeyState_UnknownFunctionKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SyncSwitchFunctionKeyState(keyEvent, KeyEvent::KEYCODE_A));
}
}
}