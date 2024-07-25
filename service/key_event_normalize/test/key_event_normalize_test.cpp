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
    ASSERT_TRUE(vKeyboard_.SetUp());
    std::cout << "device node name: " << vKeyboard_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vKeyboard_.GetDevPath()));
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
    struct libinput_device *device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
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
 * @tc.name: KeyEventNormalizeTest_ResetKeyEvent_001
 * @tc.desc: Test ResetKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_ResetKeyEvent_001, TestSize.Level1)
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
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(dev));
}

/**
 * @tc.name: KeyEventNormalizeTest_ResetKeyEvent_002
 * @tc.desc: Test ResetKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, KeyEventNormalizeTest_ResetKeyEvent_002, TestSize.Level1)
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
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(dev));
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
    ASSERT_EQ(ret, RET_OK);
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
    EXPECT_EQ(result, RET_OK);
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
    EXPECT_EQ(result, RET_OK);
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
}
}