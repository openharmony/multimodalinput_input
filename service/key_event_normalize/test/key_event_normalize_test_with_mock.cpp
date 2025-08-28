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

#include <cstdio>
#include <gtest/gtest.h>
#include "define_multimodal.h"
#include "input_device_manager.h"
#include "key_event_normalize.h"
#include "libinput_mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventNormalizeWithMockTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class KeyEventNormalizeWithMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(){};
    void TearDown(){};
};

void KeyEventNormalizeWithMockTest::SetUpTestCase(void)
{
}

void KeyEventNormalizeWithMockTest::TearDownTestCase(void)
{
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
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    // create a node for keyboard.
    struct libinput_device libDev {
        .udevDev { 1 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(testing::Return(libDev.name.data()));
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), false);
    EXPECT_EQ(INPUT_DEV_MGR->IsPointerDevice(&libDev), false);
    KeyEventHdr->keyEvent_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
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
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), true);
    EXPECT_EQ(INPUT_DEV_MGR->IsPointerDevice(&libDev), false);
    KeyEventHdr->keyEvent_ = nullptr;
    // led off
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(0));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOff_003
 * @tc.desc: Test ResetKeyEvent with a kbd device without led and valid keyEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOff_003, TestSize.Level1)
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
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), true);
    EXPECT_EQ(INPUT_DEV_MGR->IsPointerDevice(&libDev), false);
    KeyEventHdr->keyEvent_ = KeyEvent::Create();
    ASSERT_TRUE(KeyEventHdr->keyEvent_ != nullptr);
    // led off
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(0));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_004
 * @tc.desc: Test ResetKeyEvent with a kbd device with led and null keyEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_004, TestSize.Level1)
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
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), true);
    EXPECT_EQ(INPUT_DEV_MGR->IsPointerDevice(&libDev), false);
    KeyEventHdr->keyEvent_ = nullptr;
    // led on
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(1));
    // mock: all lights on.
    EXPECT_CALL(libinputMock, GetFuncKeyState).WillRepeatedly(testing::Return(1));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
    // expect: reset keyevent from device
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY), true);
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY), true);
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY), true);
}

/**
 * @tc.name: KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_005
 * @tc.desc: Test ResetKeyEvent with a kbd device with led and valid keyEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeWithMockTest, KeyEventNormalizeWithMockTest_ResetKeyEvent_Kbd_LedOn_005, TestSize.Level1)
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
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), true);
    EXPECT_EQ(INPUT_DEV_MGR->IsPointerDevice(&libDev), false);
    KeyEventHdr->keyEvent_ = KeyEvent::Create();
    ASSERT_TRUE(KeyEventHdr->keyEvent_ != nullptr);
    // original: 0, 1, 0.
    KeyEventHdr->keyEvent_->SetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY, 0);
    KeyEventHdr->keyEvent_->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, 1);
    KeyEventHdr->keyEvent_->SetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, 0);
    // led on
    EXPECT_CALL(libinputMock, HasEventLedType).WillOnce(testing::Return(1));
    // mock: all lights on.
    EXPECT_CALL(libinputMock, GetFuncKeyState).WillRepeatedly(testing::Return(1));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->ResetKeyEvent(&libDev));
    // overwritten.
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY), true);
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY), true);
    EXPECT_EQ(KeyEventHdr->keyEvent_->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY), true);
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
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
    testing::NiceMock<LibinputInterfaceMock> libinputMock;
    // create a node for keyboard.
    struct libinput_device libDev {
        .udevDev { 1 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), false);
    int32_t vKeyboardDeviceId = 0;
    auto vKeyboard = std::make_shared<InputDevice>();
    CHKPV(vKeyboard);
    vKeyboard->SetName("VirtualKeyboardTest");
    vKeyboard->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->AddVirtualInputDevice(vKeyboard, vKeyboardDeviceId);
    KeyEventHdr->keyEvent_ = nullptr;
    EXPECT_EQ(INPUT_DEV_MGR->IsVirtualKeyboardDeviceEverConnected(), true);
    // led off
    EXPECT_CALL(libinputMock, HasEventLedType).Times(testing::AtMost(1)).WillOnce(testing::Return(0));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SyncLedStateFromKeyEvent(&libDev));
    if (vKeyboardDeviceId > 0) {
        INPUT_DEV_MGR->RemoveVirtualInputDevice(vKeyboardDeviceId);
    }
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
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), true);
    int32_t vKeyboardDeviceId = 0;
    auto vKeyboard = std::make_shared<InputDevice>();
    CHKPV(vKeyboard);
    vKeyboard->SetName("VirtualKeyboardTest");
    vKeyboard->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->AddVirtualInputDevice(vKeyboard, vKeyboardDeviceId);
    KeyEventHdr->keyEvent_ = nullptr;
    EXPECT_EQ(INPUT_DEV_MGR->IsVirtualKeyboardDeviceEverConnected(), true);
    // led off
    EXPECT_CALL(libinputMock, HasEventLedType).Times(testing::AtMost(1)).WillOnce(testing::Return(0));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SyncLedStateFromKeyEvent(&libDev));
    if (vKeyboardDeviceId > 0) {
        INPUT_DEV_MGR->RemoveVirtualInputDevice(vKeyboardDeviceId);
    }
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
    EXPECT_EQ(INPUT_DEV_MGR->IsKeyboardDevice(&libDev), true);
    KeyEventHdr->keyEvent_ = nullptr;
    int32_t vKeyboardDeviceId = 0;
    auto vKeyboard = std::make_shared<InputDevice>();
    CHKPV(vKeyboard);
    vKeyboard->SetName("VirtualKeyboardTest");
    vKeyboard->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    INPUT_DEV_MGR->AddVirtualInputDevice(vKeyboard, vKeyboardDeviceId);
    EXPECT_EQ(INPUT_DEV_MGR->IsVirtualKeyboardDeviceEverConnected(), true);
    // led on
    EXPECT_CALL(libinputMock, HasEventLedType).Times(testing::AtMost(1)).WillOnce(testing::Return(1));
    EXPECT_NO_FATAL_FAILURE(KeyEventHdr->SyncLedStateFromKeyEvent(&libDev));
    if (vKeyboardDeviceId > 0) {
        INPUT_DEV_MGR->RemoveVirtualInputDevice(vKeyboardDeviceId);
    }
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}
}