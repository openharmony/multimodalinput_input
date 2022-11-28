/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class KeyEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:KeyEventTest_OnCheckKeyEvent_001
 * @tc.desc:Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_001, TestSize.Level1)
{
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
 * @tc.name:KeyEventTest_OnCheckKeyEvent_002
 * @tc.desc:Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_002, TestSize.Level1)
{
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
 * @tc.name:KeyEventTest_OnCheckKeyEvent_003
 * @tc.desc:Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_003, TestSize.Level1)
{
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
 * @tc.name:KeyEventTest_OnCheckKeyEvent_004
 * @tc.desc:Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_004, TestSize.Level1)
{
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
 * @tc.name:KeyEventTest_OnCheckKeyEvent_005
 * @tc.desc:Verify key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_005, TestSize.Level1)
{
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
 * @tc.name:KeyEventTest_OnCheckKeyEvent_006
 * @tc.desc:Verify key event
 * @tc.type: FUNC
 * @tc.require: I5QSN3
 */
HWTEST_F(KeyEventTest, KeyEventTest_OnCheckKeyEvent_006, TestSize.Level1)
{
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
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, true);
    bool result = keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: KeyEventTest_GetFunctionKey_005
 * @tc.desc: Set Scrolllock for keyevent to false
 * @tc.type: FUNC
 * @tc.require: I5HMCX
 */
HWTEST_F(KeyEventTest, KeyEventTest_GetFunctionKey_005, TestSize.Level1)
{
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
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t lockCode = keyEvent->TransitionFunctionKey(KeyEvent::KEYCODE_A);
    ASSERT_EQ(lockCode, KeyEvent::UNKOWN_FUNCTION_KEY);
}

/**
 * @tc.name: KeyEventTest_ReadFromParcel_001
 * @tc.desc: Read from parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventTest, KeyEventTest_ReadFromParcel_001, TestSize.Level1)
{
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
} // namespace MMI
} // namespace OHOS
