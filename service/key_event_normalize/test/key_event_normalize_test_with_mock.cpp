/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fstream>

#include <cJSON.h>
#include <gtest/gtest.h>
#include <linux/input.h>

#include "config_policy_utils.h"
#include "define_multimodal.h"
#include "display_manager_lite.h"
#include "input_device_manager.h"
#include "key_event_normalize.h"
#include "key_map_manager.h"
#include "libinput_adapter.h"
#include "libinput_mock.h"
#include "key_auto_repeat.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventNormalizeWithMockTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SWAP_VOLUME_KEYS_ON_FOLD_TEST { 0 };
char g_cfgName[] { "custom_input_product_config.json" };
} // namespace

using namespace testing;
using namespace testing::ext;

class KeyEventNormalizeWithMockTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown();

private:
    void SerializeInputProductConfig(cJSON *jsonProductConfig);
    void BuildVolumeSwapConfig2();
    void BuildVolumeSwapConfig3();
    void BuildVolumeSwapConfig4();
    void BuildVolumeSwapConfig5();
    void BuildVolumeSwapConfig6();
};

void KeyEventNormalizeWithMockTest::SetUp()
{
    KeyEventHdr->keyEventResetDone_ = false;
}

void KeyEventNormalizeWithMockTest::TearDown()
{
    InputDeviceManagerMock::ReleaseInstance();
    KeyMapManager::ReleaseInstance();
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_ResetKeyEvent_NonKbd_001
 * @tc.desc: Test ResetKeyEvent with a non-kbd device.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_ResetKeyEvent_NonKbd_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, IsKeyboardDevice).WillOnce(testing::Return(false));
    EXPECT_CALL(*INPUT_DEV_MGR, IsPointerDevice).WillOnce(testing::Return(false));

    KeyEventHdr->keyEvent_ = nullptr;
    struct libinput_device libDev {};
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
    EXPECT_EQ(KeyEventHdr->keyEvent_, nullptr);
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOff_002
 * @tc.desc: Test ResetKeyEvent with a kbd device without led and null keyEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOff_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, IsKeyboardDevice).WillOnce(testing::Return(true));
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(false));

    KeyEventHdr->keyEvent_ = nullptr;
    struct libinput_device libDev {};
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
    auto keyEvent = KeyEventHdr->keyEvent_;
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        const std::vector<int32_t> funcKeys {
            KeyEvent::NUM_LOCK_FUNCTION_KEY,
            KeyEvent::CAPS_LOCK_FUNCTION_KEY,
            KeyEvent::SCROLL_LOCK_FUNCTION_KEY
        };
        for (const auto &funcKey : funcKeys) {
            EXPECT_FALSE(keyEvent->GetFunctionKey(funcKey));
        }
    }
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_003
 * @tc.desc: Test ResetKeyEvent with a kbd device with led and null keyEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, IsKeyboardDevice).WillOnce(testing::Return(true));
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(true));
    EXPECT_CALL(libinputMock, GetFuncKeyState)
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(false));

    KeyEventHdr->keyEvent_ = nullptr;
    struct libinput_device libDev {};
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));

    auto keyEvent = KeyEventHdr->keyEvent_;
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        EXPECT_TRUE(keyEvent->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY));
        EXPECT_FALSE(keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY));
        EXPECT_FALSE(keyEvent->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY));
    }
}

/**
 * @tc.name: ResetKeyEvent_Kbd_LedOn_004
 * @tc.desc: Test ResetKeyEvent with a kbd device with led and valid keyEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, ResetKeyEvent_Kbd_LedOn_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, IsKeyboardDevice).WillOnce(testing::Return(true));
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(true));
    EXPECT_CALL(libinputMock, GetFuncKeyState)
        .WillOnce(testing::Return(true))
        .WillRepeatedly(testing::Return(false));

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEventHdr->keyEvent_ = keyEvent;
    struct libinput_device libDev {};
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));

    EXPECT_EQ(KeyEventHdr->keyEvent_, keyEvent);
    if (keyEvent != nullptr) {
        EXPECT_TRUE(keyEvent->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY));
        EXPECT_FALSE(keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY));
        EXPECT_FALSE(keyEvent->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY));
    }
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_OnceOnly_006
 * @tc.desc: ResetKeyEvent reads the device lock state back into keyEvent_ only once (crash
 *           recovery); subsequent calls must NOT overwrite keyEvent_, so a quirky keyboard-like
 *           device (e.g. headset) hot-plugged at runtime cannot corrupt the global lock state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_OnceOnly_006,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    // create a node for keyboard.
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(testing::Return(libDev.name.data()));
    ASSERT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), true);
    KeyEventHdr->keyEvent_ = KeyEvent::Create();
    ASSERT_TRUE(KeyEventHdr->keyEvent_ != nullptr);
    KeyEventHdr->keyEventResetDone_ = false;   // simulate fresh process (recovery)
    // 1st call: recovery -- read-back runs, overwrites keyEvent_ with device state (all lights on)
    EXPECT_CALL(libinputMock, HasEventLedType).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(libinputMock, GetFuncKeyState).WillRepeatedly(testing::Return(1));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY), true);
    // 2nd call: runtime hot-plug -- read-back MUST be skipped, keyEvent_ NOT overwritten
    KeyEventHdr->keyEvent_->SetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY, 0);
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY), false);
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_SyncLedStateFromKeyEvent_NonKbd_LedOff_001
 * @tc.desc: Test SyncLedStateFromKeyEvent with a non-kbd device without led.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_SyncLedStateFromKeyEvent_NonKbd_LedOff_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, IsKeyboardDevice).WillOnce(testing::Return(false));
    struct libinput_device libDev {};
    EXPECT_FALSE(KeyEventHdr->SyncLedStateFromKeyEvent(&libDev));
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_SyncLedStateFromKeyEvent_Kbd_LedOff_002
 * @tc.desc: Test SyncLedStateFromKeyEvent with a kbd device without led.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_SyncLedStateFromKeyEvent_Kbd_LedOff_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, IsKeyboardDevice).WillOnce(testing::Return(true));
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(false));

    struct libinput_device libDev {};
    EXPECT_FALSE(KeyEventHdr->SyncLedStateFromKeyEvent(&libDev));
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_SyncLedStateFromKeyEvent_Kbd_LedOn_003
 * @tc.desc: Test SyncLedStateFromKeyEvent with a kbd device with led.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_SyncLedStateFromKeyEvent_Kbd_LedOn_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*INPUT_DEV_MGR, IsKeyboardDevice).WillOnce(testing::Return(true));
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(true));
    testing::NiceMock<LibinputAdapter> adapterMock;
    EXPECT_CALL(adapterMock, UpdateLed).WillRepeatedly(testing::Return(RET_OK));

    struct libinput_device libDev {};
    EXPECT_TRUE(KeyEventHdr->SyncLedStateFromKeyEvent(&libDev));
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_SimulatedModifierKeyEventNormalize_NonSimulated_002
 * @tc.desc: Test SimulatedModifierKeyEventNormalize with non-simulated keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest,
    KeyEventNormalizeWithMockTest_SimulatedModifierKeyEventNormalize_NonSimulated_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEventHdr->SimulatedModifierKeyEventNormalize(keyEvent);
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_SimulatedModifierKeyEventNormalize_NonFunction_003
 * @tc.desc: Test SimulatedModifierKeyEventNormalize with non-function key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest,
    KeyEventNormalizeWithMockTest_SimulatedModifierKeyEventNormalize_NonFunc_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEventHdr->SimulatedModifierKeyEventNormalize(keyEvent);
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_SimulatedModifierKeyEventNormalize_ModifierWithShell_004
 * @tc.desc: Test SimulatedModifierKeyEventNormalize with modifier key from shell
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest,
    KeyEventNormalizeWithMockTest_SimulatedModifierKeyEventNormalize_Shell_004,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SHELL);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEventHdr->SetKeyStatusRecord(true, 5000);
    KeyEventHdr->SimulatedModifierKeyEventNormalize(keyEvent);
    KeyEventHdr->SetKeyStatusRecord(false, 10000);
}

/**
 * @tc.name: Normalize_NullEvent_001
 * @tc.desc: Test Normalize with null libinput_event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, Normalize_NullEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto ret = KeyEventHdr->Normalize(nullptr, keyEvent);
    EXPECT_EQ(ret, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: Normalize_NullKeyEvent_002
 * @tc.desc: Test Normalize with null keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, Normalize_NullKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    struct libinput_event libEvent {};
    auto ret = KeyEventHdr->Normalize(&libEvent, nullptr);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: Normalize_NullKeyboardData_003
 * @tc.desc: Test Normalize with null keyboard event data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, Normalize_NullKeyboardData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(testing::Return(nullptr));

    struct libinput_event libEvent {};
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    auto ret = KeyEventHdr->Normalize(&libEvent, keyEvent);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: Normalize_NullDevice_004
 * @tc.desc: Test Normalize with null device from event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, Normalize_NullDevice_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_event_keyboard libKbdEvent {};
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(testing::Return(&libKbdEvent));
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(testing::Return(nullptr));

    struct libinput_event libEvent {};
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    auto ret = KeyEventHdr->Normalize(&libEvent, keyEvent);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: Normalize_UnknownKeyCode_005
 * @tc.desc: Test Normalize with null device from event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, Normalize_UnknownKeyCode_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    struct libinput_event_keyboard libKbdEvent {};
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(testing::Return(&libKbdEvent));
    struct libinput_device libDev {};
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(testing::Return(&libDev));
    constexpr int32_t rawCode { -1 };
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKey).WillOnce(testing::Return(rawCode));

    constexpr int32_t deviceId { 0 };
    EXPECT_CALL(*INPUT_DEV_MGR, FindInputDeviceId).WillOnce(testing::Return(deviceId));
    EXPECT_CALL(*KeyMapMgr, TransferDeviceKeyValue).WillOnce(testing::Return(KeyEvent::KEYCODE_UNKNOWN));

    struct libinput_event libEvent {};
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    auto ret = KeyEventHdr->Normalize(&libEvent, keyEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: Normalize_KeyDownAction_006
 * @tc.desc: Test Normalize with key down action (key_state != 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, Normalize_KeyDownAction_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    struct libinput_event_keyboard libKbdEvent {};
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(testing::Return(&libKbdEvent));
    struct libinput_device libDev {};
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(testing::Return(&libDev));
    constexpr int32_t rawCode { 30 };
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKey).WillOnce(testing::Return(rawCode));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState)
        .WillRepeatedly(testing::Return(LIBINPUT_KEY_STATE_PRESSED));

    constexpr int32_t deviceId { 1 };
    EXPECT_CALL(*INPUT_DEV_MGR, FindInputDeviceId).WillOnce(testing::Return(deviceId));
    EXPECT_CALL(*KeyMapMgr, TransferDeviceKeyValue).WillOnce(testing::Return(KeyEvent::KEYCODE_A));

    struct libinput_event libEvent {};
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    auto ret = KeyEventHdr->Normalize(&libEvent, keyEvent);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(keyEvent->GetDeviceId(), deviceId);
    EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
    EXPECT_EQ(keyEvent->GetKeyCode(), KeyEvent::KEYCODE_A);
    EXPECT_TRUE(keyEvent->GetKeyItem(KeyEvent::KEYCODE_A));
}

/**
 * @tc.name: Normalize_PreActionUpWithKeyItem_007
 * @tc.desc: Test Normalize when preAction is UP and preUpKeyItem exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, Normalize_PreActionUpWithKeyItem_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    struct libinput_event_keyboard libKbdEvent {};
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(testing::Return(&libKbdEvent));
    struct libinput_device libDev {};
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(testing::Return(&libDev));
    constexpr int32_t rawCode { 30 };
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKey).WillOnce(testing::Return(rawCode));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState)
        .WillRepeatedly(testing::Return(LIBINPUT_KEY_STATE_PRESSED));

    constexpr int32_t deviceId { 1 };
    EXPECT_CALL(*INPUT_DEV_MGR, FindInputDeviceId).WillOnce(testing::Return(deviceId));
    EXPECT_CALL(*KeyMapMgr, TransferDeviceKeyValue).WillOnce(testing::Return(KeyEvent::KEYCODE_A));

    struct libinput_event libEvent {};
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_B);
    keyItem.SetPressed(false);
    keyEvent->AddPressedKeyItems(keyItem);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);

    auto ret = KeyEventHdr->Normalize(&libEvent, keyEvent);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_FALSE(keyEvent->GetKeyItem(KeyEvent::KEYCODE_B));
    auto opt = keyEvent->GetKeyItem(KeyEvent::KEYCODE_A);
    if (opt) {
        EXPECT_TRUE(opt->IsPressed());
    }
    EXPECT_TRUE(opt);
}

/**
 * @tc.name: HandleKeyAction_NullDev_001
 * @tc.desc: Test HandleKeyAction with NullDev
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, HandleKeyAction_NullDev_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetPressed(true);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UNKNOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);

    KeyEventHdr->HandleKeyAction(nullptr, keyItem, keyEvent);
    EXPECT_EQ(keyEvent->GetKeyCode(), KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_UNKNOWN);
}

/**
 * @tc.name: HandleKeyAction_NullEvent_002
 * @tc.desc: Test HandleKeyAction with NullEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, HandleKeyAction_NullEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device libDev {};
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetPressed(true);

    KeyEventHdr->HandleKeyAction(&libDev, keyItem, nullptr);
    EXPECT_EQ(keyItem.GetKeyCode(), KeyEvent::KEYCODE_A);
    EXPECT_TRUE(keyItem.IsPressed());
}

/**
 * @tc.name: HandleKeyAction_DownEvent_003
 * @tc.desc: Test HandleKeyAction with KeyDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, HandleKeyAction_DownEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device libDev {};
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetPressed(true);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEventHdr->HandleKeyAction(&libDev, keyItem, keyEvent);
    auto item = keyEvent->GetKeyItem(keyItem.GetKeyCode());
    if (item) {
        EXPECT_EQ(item->GetKeyCode(), keyItem.GetKeyCode());
        EXPECT_TRUE(item->IsPressed());
    }
    EXPECT_TRUE(item);
}

/**
 * @tc.name: HandleKeyAction_UpEvent_004
 * @tc.desc: Test HandleKeyAction with KeyUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, HandleKeyAction_UpEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device libDev {};
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetPressed(true);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->AddPressedKeyItems(keyItem);
    keyItem.SetPressed(false);

    KeyEventHdr->HandleKeyAction(&libDev, keyItem, keyEvent);
    auto item = keyEvent->GetKeyItem(keyItem.GetKeyCode());
    if (item) {
        EXPECT_EQ(item->GetKeyCode(), keyItem.GetKeyCode());
        EXPECT_FALSE(item->IsPressed());
    }
    EXPECT_TRUE(item);
}

/**
 * @tc.name: HandleKeyAction_FuncKeyUpEvent_005
 * @tc.desc: Test HandleKeyAction with FuncKeyUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, HandleKeyAction_FuncKeyUpEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetFuncKeyState).WillOnce(testing::Return(true));

    struct libinput_device libDev {};
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_CAPS_LOCK);
    keyItem.SetPressed(true);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAPS_LOCK);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->AddPressedKeyItems(keyItem);
    keyItem.SetPressed(false);

    KeyEventHdr->HandleKeyAction(&libDev, keyItem, keyEvent);
    auto item = keyEvent->GetKeyItem(keyItem.GetKeyCode());
    if (item) {
        EXPECT_EQ(item->GetKeyCode(), keyItem.GetKeyCode());
        EXPECT_FALSE(item->IsPressed());
    }
    EXPECT_TRUE(item);
    EXPECT_TRUE(keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY));
    EXPECT_FALSE(keyEvent->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY));
}

/**
 * @tc.name: HandleKeyAction_KeyCancelEvent_006
 * @tc.desc: Test HandleKeyAction with KeyCancelEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, HandleKeyAction_KeyCancelEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct libinput_device libDev {};
    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetPressed(true);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_CANCEL);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    keyEvent->AddPressedKeyItems(keyItem);

    KeyEventHdr->HandleKeyAction(&libDev, keyItem, keyEvent);
    auto item = keyEvent->GetKeyItem(keyItem.GetKeyCode());
    if (item) {
        EXPECT_EQ(item->GetKeyCode(), keyItem.GetKeyCode());
        EXPECT_TRUE(item->IsPressed());
    }
    EXPECT_TRUE(item);
}

/**
 * @tc.name: ReadProductConfig_001
 * @tc.desc: Test ReadProductConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, ReadProductConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(nullptr));

    KeyEventNormalize::InputProductConfig productCfg {};
    KeyEventHdr->ReadProductConfig(productCfg);
    EXPECT_EQ(productCfg.volumeSwap_, KeyEventNormalize::VolumeSwapConfig::NO_CONFIG);
}

void KeyEventNormalizeWithMockTest::SerializeInputProductConfig(cJSON *jsonProductConfig)
{
    CHKPV(jsonProductConfig);
    auto sProductConfig = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonProductConfig),
        [](char *object) {
            if (object != nullptr) {
                cJSON_free(object);
            }
        });
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << sProductConfig.get();
        ofs.flush();
        ofs.close();
    }
}

void KeyEventNormalizeWithMockTest::BuildVolumeSwapConfig2()
{
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << "tail";
        ofs.flush();
        ofs.close();
    }
}

/**
 * @tc.name: ReadProductConfig_002
 * @tc.desc: Test ReadProductConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, ReadProductConfig_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildVolumeSwapConfig2();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    KeyEventNormalize::InputProductConfig productCfg {};
    KeyEventHdr->ReadProductConfig(productCfg);
    EXPECT_EQ(productCfg.volumeSwap_, KeyEventNormalize::VolumeSwapConfig::NO_CONFIG);
    std::filesystem::remove(g_cfgName);
}

void KeyEventNormalizeWithMockTest::BuildVolumeSwapConfig3()
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    SerializeInputProductConfig(jsonProductConfig.get());
}

/**
 * @tc.name: ReadProductConfig_003
 * @tc.desc: Test ReadProductConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, ReadProductConfig_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildVolumeSwapConfig3();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    KeyEventNormalize::InputProductConfig productCfg {};
    KeyEventHdr->ReadProductConfig(productCfg);
    EXPECT_EQ(productCfg.volumeSwap_, KeyEventNormalize::VolumeSwapConfig::NO_CONFIG);
    std::filesystem::remove(g_cfgName);
}

void KeyEventNormalizeWithMockTest::BuildVolumeSwapConfig4()
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonProductConfig);
    auto jsonKeyboard = cJSON_CreateObject();
    CHKPV(jsonKeyboard);
    if (!cJSON_AddItemToObject(jsonProductConfig.get(), "keyboard", jsonKeyboard)) {
        cJSON_Delete(jsonKeyboard);
        return;
    }
    SerializeInputProductConfig(jsonProductConfig.get());
}

/**
 * @tc.name: ReadProductConfig_004
 * @tc.desc: Test ReadProductConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, ReadProductConfig_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildVolumeSwapConfig4();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    KeyEventNormalize::InputProductConfig productCfg {};
    KeyEventHdr->ReadProductConfig(productCfg);
    EXPECT_EQ(productCfg.volumeSwap_, KeyEventNormalize::VolumeSwapConfig::NO_CONFIG);
    std::filesystem::remove(g_cfgName);
}

void KeyEventNormalizeWithMockTest::BuildVolumeSwapConfig5()
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonProductConfig);
    auto jsonKeyboard = cJSON_CreateObject();
    CHKPV(jsonKeyboard);
    if (!cJSON_AddItemToObject(jsonProductConfig.get(), "keyboard", jsonKeyboard)) {
        cJSON_Delete(jsonKeyboard);
        return;
    }
    cJSON *jsonVolumeSwap = cJSON_CreateObject();
    CHKPV(jsonVolumeSwap);
    if (!cJSON_AddItemToObject(jsonKeyboard, "volumeSwap", jsonVolumeSwap)) {
        cJSON_Delete(jsonVolumeSwap);
        return;
    }
    SerializeInputProductConfig(jsonProductConfig.get());
}

/**
 * @tc.name: ReadProductConfig_005
 * @tc.desc: Test ReadProductConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, ReadProductConfig_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildVolumeSwapConfig5();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    KeyEventNormalize::InputProductConfig productCfg {};
    KeyEventHdr->ReadProductConfig(productCfg);
    EXPECT_EQ(productCfg.volumeSwap_, KeyEventNormalize::VolumeSwapConfig::NO_CONFIG);
    std::filesystem::remove(g_cfgName);
}

void KeyEventNormalizeWithMockTest::BuildVolumeSwapConfig6()
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonProductConfig);
    auto jsonKeyboard = cJSON_CreateObject();
    CHKPV(jsonKeyboard);
    if (!cJSON_AddItemToObject(jsonProductConfig.get(), "keyboard", jsonKeyboard)) {
        cJSON_Delete(jsonKeyboard);
        return;
    }
    cJSON *jsonVolumeSwap = cJSON_CreateObject();
    CHKPV(jsonVolumeSwap);
    if (!cJSON_AddItemToObject(jsonKeyboard, "volumeSwap", jsonVolumeSwap)) {
        cJSON_Delete(jsonVolumeSwap);
        return;
    }
    cJSON *jsonWhen = cJSON_CreateNumber(SWAP_VOLUME_KEYS_ON_FOLD_TEST);
    CHKPV(jsonWhen);
    if (!cJSON_AddItemToObject(jsonVolumeSwap, "when", jsonWhen)) {
        cJSON_Delete(jsonWhen);
        return;
    }
    SerializeInputProductConfig(jsonProductConfig.get());
}

/**
 * @tc.name: ReadProductConfig_006
 * @tc.desc: Test ReadProductConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, ReadProductConfig_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildVolumeSwapConfig6();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    KeyEventNormalize::InputProductConfig productCfg {};
    KeyEventHdr->ReadProductConfig(productCfg);
    EXPECT_EQ(productCfg.volumeSwap_, KeyEventNormalize::VolumeSwapConfig::SWAP_ON_FOLD);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: TransformVolumeKey_001
 * @tc.desc: Test TransformVolumeKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, TransformVolumeKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildVolumeSwapConfig6();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    struct libinput_device libDev {};
    int32_t keyCode { KeyEvent::KEYCODE_A };
    int32_t keyAction { KeyEvent::KEY_ACTION_DOWN };
    auto transformed = KeyEventHdr->TransformVolumeKey(&libDev, keyCode, keyAction);
    EXPECT_EQ(transformed, KeyEvent::KEYCODE_A);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: TransformVolumeKey_002
 * @tc.desc: Test TransformVolumeKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, TransformVolumeKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    char devName[] { "DUMMY" };
    EXPECT_CALL(libinputMock, DeviceGetName).WillOnce(testing::Return(devName));

    BuildVolumeSwapConfig6();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    Rosen::DisplayManagerLite::GetInstance().NotifyFoldStatusChanged(Rosen::FoldStatus::FOLDED);

    struct libinput_device libDev {
        .busType = BUS_HOST,
    };
    int32_t keyCode { KeyEvent::KEYCODE_VOLUME_DOWN };
    int32_t keyAction { KeyEvent::KEY_ACTION_DOWN };
    auto transformed = KeyEventHdr->TransformVolumeKey(&libDev, keyCode, keyAction);
    EXPECT_EQ(transformed, KeyEvent::KEYCODE_VOLUME_UP);
}
} // namespace MMI
} // namespace OHOS
