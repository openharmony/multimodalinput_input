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

#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "event_util_test.h"
#include "input_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "proto.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class KeyEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyEventTest_OnCheckKeyEvent_001
 * @tc.desc: Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    ASSERT_TRUE(!KeyEvent->IsValid());

    KeyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent->SetActionTime(0);
    ASSERT_TRUE(!KeyEvent->IsValid());

    KeyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent->SetActionTime(100);
    KeyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    ASSERT_TRUE(!KeyEvent->IsValid());
}

/**
 * @tc.name: KeyEventTest_OnCheckKeyEvent_002
 * @tc.desc: Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto KeyEvent1 = KeyEvent::Create();
    ASSERT_NE(KeyEvent1, nullptr);
    KeyEvent1->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent1->SetActionTime(100);
    KeyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    KeyEvent1->AddKeyItem(item);
    ASSERT_TRUE(!KeyEvent1->IsValid());

    auto KeyEvent2 = KeyEvent::Create();
    ASSERT_NE(KeyEvent2, nullptr);
    KeyEvent2->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent2->SetActionTime(100);
    KeyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item.SetDownTime(0);
    KeyEvent2->AddKeyItem(item);
    ASSERT_TRUE(!KeyEvent2->IsValid());
}

/**
 * @tc.name: KeyEventTest_OnCheckKeyEvent_003
 * @tc.desc: Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto KeyEvent1 = KeyEvent::Create();
    ASSERT_NE(KeyEvent1, nullptr);
    KeyEvent1->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent1->SetActionTime(100);
    KeyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item.SetDownTime(100);
    item.SetPressed(false);
    KeyEvent1->AddKeyItem(item);
    ASSERT_TRUE(!KeyEvent1->IsValid());

    auto KeyEvent2 = KeyEvent::Create();
    ASSERT_NE(KeyEvent2, nullptr);
    KeyEvent2->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent2->SetActionTime(100);
    KeyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.SetKeyCode(KeyEvent::KEYCODE_BACK);
    item.SetDownTime(100);
    item.SetPressed(false);
    KeyEvent2->AddKeyItem(item);
    ASSERT_TRUE(!KeyEvent2->IsValid());
}

/**
 * @tc.name: KeyEventTest_OnCheckKeyEvent_004
 * @tc.desc: Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto KeyEvent1 = KeyEvent::Create();
    ASSERT_NE(KeyEvent1, nullptr);
    KeyEvent1->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent1->SetActionTime(100);
    KeyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    KeyEvent1->AddKeyItem(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item2.SetDownTime(100);
    item2.SetPressed(false);
    KeyEvent1->AddKeyItem(item2);
    ASSERT_TRUE(!KeyEvent1->IsValid());

    auto KeyEvent2 = KeyEvent::Create();
    ASSERT_NE(KeyEvent2, nullptr);
    KeyEvent2->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent2->SetActionTime(100);
    KeyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ASSERT_TRUE(!KeyEvent2->IsValid());
}

/**
 * @tc.name: KeyEventTest_OnCheckKeyEvent_005
 * @tc.desc: Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto KeyEvent1 = KeyEvent::Create();
    ASSERT_NE(KeyEvent1, nullptr);
    KeyEvent1->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent1->SetActionTime(100);
    KeyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    KeyEvent1->AddKeyItem(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_BACK);
    item2.SetDownTime(100);
    item2.SetPressed(true);
    KeyEvent1->AddKeyItem(item2);
    ASSERT_TRUE(KeyEvent1->IsValid());

    auto KeyEvent2 = KeyEvent::Create();
    ASSERT_NE(KeyEvent2, nullptr);
    KeyEvent2->SetKeyCode(KeyEvent::KEYCODE_HOME);
    KeyEvent2->SetActionTime(100);
    KeyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item1.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item1.SetDownTime(100);
    item1.SetPressed(true);
    KeyEvent2->AddKeyItem(item1);
    ASSERT_TRUE(KeyEvent2->IsValid());
}

/**
 * @tc.name: KeyEventTest_OnCheckKeyEvent_006
 * @tc.desc: Verify key event
 * @tc.type: FUNC
 * @tc.require: I5QSN3
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    auto event1 = KeyEvent::from(inputEvent);
    ASSERT_EQ(event1, nullptr);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto event2 = KeyEvent::Clone(keyEvent);
    ASSERT_NE(event2, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEvent->SetActionTime(100);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    keyEvent->ActionToString(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->KeyCodeToString(KeyEvent::KEYCODE_BACK);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_BACK);
    item.SetDownTime(100);
    item.SetPressed(true);
    item.SetUnicode(0);
    keyEvent->AddKeyItem(item);
    ASSERT_TRUE(keyEvent->IsValid());
    std::vector<KeyEvent::KeyItem> items = keyEvent->GetKeyItems();
    TestUtil->DumpInputEvent(keyEvent);
}

/**
 * @tc.name: KeyEventTest_GetFunctionKey_001
 * @tc.desc: Set Numlock for keyevent to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetFunctionKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY, false);
    bool result = keyEvent->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: KeyEventTest_GetFunctionKey_002
 * @tc.desc: Set Numlock for keyevent to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetFunctionKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY, true);
    bool result = keyEvent->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: KeyEventTest_GetFunctionKey_003
 * @tc.desc: Set Capslock for keyevent to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetFunctionKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, false);
    bool result = keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: KeyEventTest_GetFunctionKey_004
 * @tc.desc: Set Capslock for keyevent to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetFunctionKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, true);
    bool result = keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: KeyEventTest_GetKeyIntention_001
 * @tc.desc: GetKey intention
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetKeyIntention_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t result = keyEvent->GetKeyIntention();
    ASSERT_EQ(result, -1);
}

/**
 * @tc.name: KeyEventTest_GetFunctionKey_005
 * @tc.desc: Set Scrolllock for keyevent to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetFunctionKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, false);
    bool result = keyEvent->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: KeyEventTest_GetFunctionKey_006
 * @tc.desc: Set Scrolllock for keyevent to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetFunctionKey_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, true);
    bool result = keyEvent->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: KeyEventTest_TransitionFunctionKey_001
 * @tc.desc: Transition keycode to function key
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_TransitionFunctionKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t lockCode = keyEvent->TransitionFunctionKey(KeyEvent::KEYCODE_NUM_LOCK);
    ASSERT_EQ(lockCode, KeyEvent::NUM_LOCK_FUNCTION_KEY);
}

/**
 * @tc.name: KeyEventTest_TransitionFunctionKey_002
 * @tc.desc: Transition keycode to function key
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_TransitionFunctionKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t lockCode = keyEvent->TransitionFunctionKey(KeyEvent::KEYCODE_SCROLL_LOCK);
    ASSERT_EQ(lockCode, KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
}

/**
 * @tc.name: KeyEventTest_TransitionFunctionKey_003
 * @tc.desc: Transition keycode to function key
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_TransitionFunctionKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t lockCode = keyEvent->TransitionFunctionKey(KeyEvent::KEYCODE_CAPS_LOCK);
    ASSERT_EQ(lockCode, KeyEvent::CAPS_LOCK_FUNCTION_KEY);
}

/**
 * @tc.name: KeyEventTest_TransitionFunctionKey_004
 * @tc.desc: Transition not support keycode to function key
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_TransitionFunctionKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t lockCode = keyEvent->TransitionFunctionKey(KeyEvent::KEYCODE_A);
    ASSERT_EQ(lockCode, KeyEvent::UNKNOWN_FUNCTION_KEY);
}

/**
 * @tc.name: KeyEventTest_ReadFromParcel_001
 * @tc.desc: Read from parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ReadFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(100);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->ActionToString(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->KeyCodeToString(KeyEvent::KEYCODE_HOME);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item.SetDownTime(100);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    MessageParcel data;
    bool ret = keyEvent->WriteToParcel(data);
    ASSERT_TRUE(ret);
    ret = keyEvent->ReadFromParcel(data);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyEventTest_ReadFromParcel_002
 * @tc.desc: Read from parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ReadFromParcel_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(100);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->ActionToString(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->KeyCodeToString(KeyEvent::KEYCODE_HOME);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item.SetDownTime(100);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    MessageParcel data;
    bool ret = keyEvent->WriteToParcel(data);
    ASSERT_TRUE(ret);
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    ret = inputEvent->ReadFromParcel(data);
    ASSERT_TRUE(ret);
    int32_t keyCode;
    ret = data.ReadInt32(keyCode);
    ASSERT_TRUE(ret);
    const int32_t keysSize = data.ReadInt32();
    ASSERT_FALSE(keysSize < 0);
    for (int32_t i = 0; i < keysSize; ++i) {
        KeyEvent::KeyItem keyItem = {};
        ret = keyItem.ReadFromParcel(data);
        ASSERT_TRUE(ret);
    }
}

/**
 * @tc.name: KeyEventTest_ReadFromParcel_003
 * @tc.desc: Verify keyoption read from parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ReadFromParcel_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys(preKeys);
    MessageParcel data;
    bool ret = keyOption->ReadFromParcel(data);
    ASSERT_FALSE(ret);
    preKeys.insert(0);
    preKeys.insert(1);
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(0);
    keyOption->SetFinalKeyDown(0);
    keyOption->SetFinalKeyDownDuration(0);
    keyOption->SetFinalKeyUpDelay(0);
    keyOption->WriteToParcel(data);
    ret = keyOption->ReadFromParcel(data);
    ASSERT_TRUE(ret);
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
/**
 * @tc.name: KeyEventTest_SetEnhanceData_001
 * @tc.desc: Set the enhance data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_SetEnhanceData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    uint32_t enHanceDataLen = 3;
    uint8_t enhanceDataBuf[enHanceDataLen];
    std::vector<uint8_t> enhanceData;
    for (uint32_t i = 0; i < enHanceDataLen; i++) {
        enhanceData.push_back(enhanceDataBuf[i]);
    }

    ASSERT_NO_FATAL_FAILURE(KeyEvent->SetEnhanceData(enhanceData));
    ASSERT_EQ(KeyEvent->GetEnhanceData(), enhanceData);
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

/**
 * @tc.name: KeyEventTest_IsRepeat_001
 * @tc.desc: Set repeat_ to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_IsRepeat_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetRepeat(false);
    bool result = keyEvent->IsRepeat();
    ASSERT_FALSE(result);
}

/**
 * @tc.name: KeyEventTest_IsRepeat_002
 * @tc.desc: Set repeat_ to true
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_IsRepeat_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetRepeat(true);
    bool result = keyEvent->IsRepeat();
    ASSERT_TRUE(result);
}

/**
 * @tc.name: KeyEventTest_Reset
 * @tc.desc: Test Reset
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_Reset, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(keyEvent->Reset());
}

/**
 * @tc.name: KeyEventTest_ToString
 * @tc.desc: Test the funcation ToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ToString, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(keyEvent->ToString());
}

/**
 * @tc.name: KeyEventTest_SetKeyItem_001
 * @tc.desc: Test the funcation SetKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_SetKeyItem_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::vector<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItems();
    ASSERT_NO_FATAL_FAILURE(keyEvent->SetKeyItem(keyItem));
}

/**
 * @tc.name: KeyEventTest_IsRepeatKey_001
 * @tc.desc: Test the funcation IsRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_IsRepeatKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_FALSE(keyEvent->IsRepeatKey());
}

/**
 * @tc.name: KeyEventTest_SetRepeatKey_001
 * @tc.desc: Test the funcation SetRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_SetRepeatKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool repeatKey = true;
    ASSERT_NO_FATAL_FAILURE(keyEvent->SetRepeatKey(repeatKey));
    repeatKey = false;
    ASSERT_NO_FATAL_FAILURE(keyEvent->SetRepeatKey(repeatKey));
}

/**
 * @tc.name: KeyEventTest_SetFourceMonitorFlag
 * @tc.desc: Test the funcation SetFourceMonitorFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_SetFourceMonitorFlag, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool fourceMonitorFlag = false;
    ASSERT_NO_FATAL_FAILURE(keyEvent->SetFourceMonitorFlag(fourceMonitorFlag));
    fourceMonitorFlag = true;
    ASSERT_NO_FATAL_FAILURE(keyEvent->SetFourceMonitorFlag(fourceMonitorFlag));
}

/**
 * @tc.name: CloneTest
 * @tc.desc: Test the funcation Clone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, CloneTest1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(keyEvent->Clone(nullptr));
}

/**
 * @tc.name: KeyEventTest_ToString_002
 * @tc.desc: Verify ToString when KeyEvent has multiple KeyItems
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ToString_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(100);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem keyItem1;
    keyItem1.SetPressed(true);
    keyItem1.SetDeviceId(1);
    keyItem1.SetKeyCode(100);
    keyItem1.SetDownTime(123456789);
    keyItem1.SetUnicode(65); // 'A'
    keyEvent->AddKeyItem(keyItem1);
    KeyEvent::KeyItem keyItem2;
    keyItem2.SetPressed(false);
    keyItem2.SetDeviceId(2);
    keyItem2.SetKeyCode(200);
    keyItem2.SetDownTime(987654321);
    keyItem2.SetUnicode(66); // 'B'
    keyEvent->AddKeyItem(keyItem2);
    std::string result;
    ASSERT_NO_FATAL_FAILURE(result = keyEvent->ToString());
    EXPECT_NE(result.find("keyCode:100"), std::string::npos);
    EXPECT_NE(result.find("keyItems:["), std::string::npos);
    EXPECT_NE(result.find("deviceId:1"), std::string::npos);
    EXPECT_NE(result.find("deviceId:2"), std::string::npos);
}

/**
 * @tc.name: KeyEventTest_KeyCodeToString_001
 * @tc.desc: Verify KeyCodeToString returns correct string when keyCode is found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_KeyCodeToString_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const int32_t keyCode = KeyEvent::KEYCODE_A;
    const char* result = KeyEvent::KeyCodeToString(keyCode);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "KEYCODE_A");
}

/**
 * @tc.name: KeyEventTest_KeyCodeToString_002
 * @tc.desc: Verify KeyCodeToString returns "KEYCODE_INVALID" when keyCode is not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_KeyCodeToString_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t invalidKeyCode = -999;
    const char* result = nullptr;
    ASSERT_NO_FATAL_FAILURE(result = KeyEvent::KeyCodeToString(invalidKeyCode));
    EXPECT_STREQ(result, "KEYCODE_INVALID");
}

/**
 * @tc.name: KeyEventTest_ReadEnhanceDataFromParcel_001
 * @tc.desc: Verify ReadEnhanceDataFromParcel returns true with valid enhance data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ReadEnhanceDataFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    int32_t size = 3;
    parcel.WriteInt32(size);
    for (int32_t i = 0; i < size; i++) {
        parcel.WriteUint32(static_cast<uint32_t>(i + 100));
    }
    KeyEvent keyEvent(InputEvent::EVENT_TYPE_KEY);
    bool ret = keyEvent.ReadEnhanceDataFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeyEventTest_ReadEnhanceDataFromParcel_002
 * @tc.desc: Verify ReadEnhanceDataFromParcel returns false when size < 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ReadEnhanceDataFromParcel_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(-5);
    KeyEvent keyEvent(InputEvent::EVENT_TYPE_KEY);
    bool ret = keyEvent.ReadEnhanceDataFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyEventTest_ReadEnhanceDataFromParcel_003
 * @tc.desc: Verify ReadEnhanceDataFromParcel returns false when size > MAX_N_ENHANCE_DATA_SIZE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ReadEnhanceDataFromParcel_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(64 + 1);
    KeyEvent keyEvent(InputEvent::EVENT_TYPE_KEY);
    bool ret = keyEvent.ReadEnhanceDataFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyEventTest_Hash_001
 * @tc.desc: Verify Hash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_Hash_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto KeyEvent = KeyEvent::Create();
    CHKPV(KeyEvent);
    auto KeyEvent2 = KeyEvent::Create();
    CHKPV(KeyEvent2);
    EXPECT_EQ(KeyEvent->Hash(), KeyEvent2->Hash());
}

/**
 * @tc.name: KeyEventTest_IsKeyPressed
 * @tc.desc: Verify IsKeyPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_IsKeyPressed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t keyCode = KeyEvent::KEYCODE_A;
    auto result = keyEvent->IsKeyPressed(keyCode);
    ASSERT_FALSE(result);
    auto ret = keyEvent->HasKeyItem(keyCode);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: Test_RemoveReleasedKeyItems_WhenMixedStates_ExpectKeepPressed
 * @tc.desc: Remove released key items when mixed states - expect pressed items to remain.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, Test_RemoveReleasedKeyItems_WhenMixedStates_ExpectKeepPressed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem keyItem;
    keyItem.SetPressed(true);
    keyEvent->keys_.push_back(keyItem);
    keyItem.SetPressed(false);
    keyEvent->keys_.push_back(keyItem);
    keyEvent->keys_.push_back(keyItem);
    ASSERT_EQ(keyEvent->keys_.size(), 3);
    EXPECT_NO_FATAL_FAILURE(keyEvent->RemoveReleasedKeyItems());
    ASSERT_EQ(keyEvent->keys_.size(), 1);
}
} // namespace MMI
} // namespace OHOS
