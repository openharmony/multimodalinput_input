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

#include <semaphore.h>

#include "event_log_helper.h"
#include "event_util_test.h"
#include "input_manager.h"
#include "input_manager_util.h"
#include "multimodal_event_handler.h"
#include "system_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerInjectTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t TIME_WAIT_FOR_OP = 100;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t POINTER_ITEM_DISPLAY_X_ONE = 147;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_TWO = 258;
constexpr int32_t INVAID_VALUE = -1;
constexpr double POINTER_ITEM_PRESSURE = 5.0;
} // namespace

class InputManagerInjectTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    std::string GetEventDump();
    void SetKeyEvent(int32_t act, int32_t code, bool pressed, int32_t time);
    void SetPointerEvent(int32_t id, int32_t pressed, int32_t action, int32_t type);
    void SetItemPointerEvent(int32_t id, int32_t pressed, int32_t action, int32_t type);

private:
    int32_t keyboardRepeatRate_ { 50 };
    int32_t keyboardRepeatDelay_ { 500 };
};

void InputManagerInjectTest::SetUpTestCase()
{
    ASSERT_TRUE(TestUtil->Init());
}

void InputManagerInjectTest::SetUp()
{
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
}

void InputManagerInjectTest::TearDown()
{
    TestUtil->AddEventDump("");
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->SetKeyboardRepeatDelay(keyboardRepeatDelay_);
    InputManager::GetInstance()->SetKeyboardRepeatRate(keyboardRepeatRate_);
}

std::string InputManagerInjectTest::GetEventDump()
{
    return TestUtil->GetEventDump();
}

void InputManagerInjectTest::SetKeyEvent(int32_t act, int32_t code, bool pressed, int32_t time)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(act);
    keyEvent->SetRepeat(true);
    item.SetKeyCode(code);
    item.SetPressed(pressed);
    item.SetDownTime(time);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
}

void InputManagerInjectTest::SetPointerEvent(int32_t id, int32_t pressed, int32_t action, int32_t type)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(id);
    pointerEvent->SetButtonPressed(pressed);

    pointerEvent->SetPointerAction(action);
    pointerEvent->SetSourceType(type);
    pointerEvent->SetPointerId(0);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

void InputManagerInjectTest::SetItemPointerEvent(int32_t id, int32_t pressed, int32_t action, int32_t type)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetPressure(POINTER_ITEM_PRESSURE);
    item.SetPointerId(0);
    pointerEvent->SetButtonId(id);
    pointerEvent->SetButtonPressed(pressed);

    pointerEvent->SetPointerAction(action);
    pointerEvent->SetSourceType(type);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

/**
 * @tc.name: InputManager_InjectEvent_004
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_004");
    };
    auto monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.SetKeyCode(KeyEvent::KEYCODE_F1);
    item.SetPressed(false);
    item.SetDownTime(500);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_005
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_005");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRepeat(true);
    item.SetKeyCode(KeyEvent::KEYCODE_SPACE);
    item.SetPressed(true);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_006
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_006");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto keyDownEvent = KeyEvent::Create();
    ASSERT_NE(keyDownEvent, nullptr);
    keyDownEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    std::vector<int32_t> downKey;
    downKey.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    downKey.push_back(KeyEvent::KEYCODE_C);

    KeyEvent::KeyItem downItem[downKey.size()];
    for (size_t i = 0; i < downKey.size(); i++) {
        keyDownEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
        keyDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        downItem[i].SetKeyCode(downKey[i]);
        downItem[i].SetPressed(true);
        downItem[i].SetDownTime(500);
        keyDownEvent->AddPressedKeyItems(downItem[i]);
    }
    InputManager::GetInstance()->SimulateInputEvent(keyDownEvent);

    auto keyUpEvent = KeyEvent::Create();
    ASSERT_NE(keyUpEvent, nullptr);
    keyUpEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    std::vector<int32_t> upKey;
    upKey.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    upKey.push_back(KeyEvent::KEYCODE_C);

    KeyEvent::KeyItem upItem[upKey.size()];
    for (size_t i = 0; i < upKey.size(); i++) {
        keyUpEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
        keyUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        upItem[i].SetKeyCode(upKey[i]);
        upItem[i].SetPressed(true);
        upItem[i].SetDownTime(0);
        keyUpEvent->RemoveReleasedKeyItems(upItem[i]);
    }
    InputManager::GetInstance()->SimulateInputEvent(keyUpEvent);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_007
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_007");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.SetKeyCode(KeyEvent::KEYCODE_F1);
    item.SetPressed(false);
    item.SetDownTime(-500);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_008
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_008");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRepeat(true);
    item.SetKeyCode(KeyEvent::KEYCODE_SPACE);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_009
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_009");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto keyDownEvent = KeyEvent::Create();
    ASSERT_NE(keyDownEvent, nullptr);
    keyDownEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    std::vector<int32_t> downKey;
    downKey.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    downKey.push_back(KeyEvent::KEYCODE_C);

    KeyEvent::KeyItem downItem[downKey.size()];
    for (size_t i = 0; i < downKey.size(); i++) {
        keyDownEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
        keyDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        downItem[i].SetKeyCode(downKey[i]);
        downItem[i].SetPressed(true);
        downItem[i].SetDownTime(500);
        keyDownEvent->AddPressedKeyItems(downItem[i]);
    }
    InputManager::GetInstance()->SimulateInputEvent(keyDownEvent);

    auto keyUpEvent = KeyEvent::Create();
    ASSERT_NE(keyUpEvent, nullptr);
    keyUpEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    std::vector<int32_t> upKey;
    upKey.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    upKey.push_back(KeyEvent::KEYCODE_V);

    KeyEvent::KeyItem upItem[upKey.size()];
    for (size_t i = 0; i < upKey.size(); i++) {
        keyUpEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
        keyUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        upItem[i].SetKeyCode(upKey[i]);
        upItem[i].SetPressed(true);
        upItem[i].SetDownTime(0);
        keyUpEvent->RemoveReleasedKeyItems(upItem[i]);
    }
    InputManager::GetInstance()->SimulateInputEvent(keyUpEvent);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_010
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_010");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_DPAD_DOWN,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_011
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_011");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_ESCAPE,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_012
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_012");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_6,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_013
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_013");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_MINUS,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_014
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_014");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_HOME,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_015
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_015");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_DEL,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_016
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_016");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_BUTTON_L1,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_017
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_017");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_SPACE,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_018
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_018");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    SetKeyEvent(KeyEvent::KEY_ACTION_DOWN, KeyEvent::KEYCODE_BRIGHTNESS_UP,
        true, 200);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectEvent_019
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectEvent_019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = true;
    auto keyEventFun = [&ret](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGI("Add monitor InjectEvent_019");
    };
    auto monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.SetKeyCode(-1);
    item.SetPressed(true);
    item.SetDownTime(500);
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    ASSERT_TRUE(ret);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SubscribeKeyEvent_004
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SubscribeKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEventFun = [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent, MMI_LOG_HEADER);
        MMI_HILOGI("Add monitor SubscribeKeyEvent_004");
    };
    auto monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);

    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(INVAID_VALUE);
    int32_t subscribeId = INVAID_VALUE;
    subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, keyEventFun);

    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SubscribeKeyEvent_005
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SubscribeKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEventFun = [](std::shared_ptr<KeyEvent> keyEvent) {
        EventLogHelper::PrintEventData(keyEvent, MMI_LOG_HEADER);
        MMI_HILOGI("Add monitor SubscribeKeyEvent_005");
    };
    auto monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);

    std::set<int32_t> preKeys;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(INVAID_VALUE);
    int32_t subscribeId = INVAID_VALUE;
    subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, keyEventFun);

    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    kitDown.SetPressed(true);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    injectDownEvent->AddPressedKeyItems(kitDown);
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_006
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_006");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_007
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_007");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_008
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_008");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_MIDDLE);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_MIDDLE);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_009
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_009");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_010
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_010");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_011
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_011");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_012
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_012");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_013
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_013");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_014
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_014");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_015
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_015");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_016
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_016");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_SIDE);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_MIDDLE);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_017
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_017");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_MIDDLE);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_SIDE);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_018
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_018");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_019
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectMouseEvent_019");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(2000);
    item.SetDisplayY(2000);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchpadEvent_001
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchpadEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchpadEvent_001");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchpadEvent_002
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchpadEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchpadEvent_002");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchpadEvent_003
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchpadEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchpadEvent_003");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchpadEvent_004
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchpadEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchpadEvent_004");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchpadEvent_005
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:AR000GJG6G
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchpadEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchpadEvent_005");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchpadEvent_006
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:AR000GJG6G
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchpadEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchpadEvent_006");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_001
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_001");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_002
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_002");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_003
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_003");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_004
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_004");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    item.SetDownTime(500);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_005
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_005");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_006
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_006");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_007
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_007");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_008
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_008");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_009
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_009");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_010
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_010");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_011
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_011");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectTouchscreenEvent_012
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectTouchscreenEvent_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor InjectTouchscreenEvent_012");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SimulateInputEventZorder_002
 * @tc.desc: Simulate input evnet with zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SimulateInputEventZorder_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor SimulateInputEventZorder_002");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetPressure(POINTER_ITEM_PRESSURE);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetZOrder(10.0);
    
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, 10.0);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SimulateInputEventZorder_003
 * @tc.desc: Simulate input evnet with zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SimulateInputEventZorder_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor SimulateInputEventZorder_003");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetPressure(POINTER_ITEM_PRESSURE);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetZOrder(-1000.0);
    
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, -1000.0);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SimulateInputEventZorder_004
 * @tc.desc: Simulate input evnet with zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SimulateInputEventZorder_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor SimulateInputEventZorder_004");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetPressure(POINTER_ITEM_PRESSURE);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetZOrder(10.0);
    
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, 10.0);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SimulateInputEventZorder_005
 * @tc.desc: Simulate input evnet with zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SimulateInputEventZorder_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor SimulateInputEventZorder_005");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetPressure(POINTER_ITEM_PRESSURE);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetZOrder(10.0);
    
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, 10.0);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SimulateInputEventZorder_006
 * @tc.desc: Simulate input evnet with zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SimulateInputEventZorder_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor SimulateInputEventZorder_006");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetPressure(POINTER_ITEM_PRESSURE);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetZOrder(10.0);
    
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, 10.0);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SimulateInputEventZorder_007
 * @tc.desc: Simulate input evnet with zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SimulateInputEventZorder_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor SimulateInputEventZorder_007");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetZOrder(10.0);
    
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, 10.0);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerTest_SimulateInputEventZorder_008
 * @tc.desc: Simulate input evnet with zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManagerTest_SimulateInputEventZorder_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) {
        MMI_HILOGI("Add monitor SimulateInputEventZorder_008");
    };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
    ASSERT_NE(monitorId, ERROR_UNSUPPORT);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetZOrder(20.0);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, 10.0);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManager_InjectMouseEvent_020
 * @tc.desc: Injection interface detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInjectTest, InputManager_InjectMouseEvent_020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputManager::GetInstance()->EnableHardwareCursorStats(true);
    InputManager::GetInstance()->MoveMouse(200, 200);
    InputManager::GetInstance()->EnableHardwareCursorStats(false);
    uint32_t frameCount = 1;
    uint32_t vsyncCount = 1;
    InputManager::GetInstance()->GetHardwareCursorStats(frameCount, vsyncCount);
    ASSERT_NE(frameCount, 1);
    ASSERT_NE(vsyncCount, 1);
}

HWTEST_F(InputManagerInjectTest, TestSimulateTouchPadEvent_001, TestSize.Level1)
{
    int32_t disPlayX[3] = {893, 52, 81 };
    int32_t disPlayY[3] = {620, 37, 46 };

    int32_t fingerCount = 3;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(0);
    pointerEvent->SetOriginPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetFingerCount(fingerCount);
    pointerEvent->SetPointerId(fingerCount - 1);
    int64_t actionTimeBase = GetSysClockTime();
    pointerEvent->SetActionTime(actionTimeBase);
    pointerEvent->SetActionStartTime(actionTimeBase);
    PointerEvent::PointerItem item;
    item.SetDownTime(pointerEvent->GetActionStartTime());
    item.SetDisplayX(disPlayX[0]);
    item.SetDisplayY(disPlayY[0]);
    pointerEvent->AddPointerItem(item);
    for (int32_t j = 1; j < fingerCount; j++) {
        PointerEvent::PointerItem itemFirst;
        itemFirst.SetPointerId(j);
        itemFirst.SetDownTime(actionTimeBase);
        itemFirst.SetDisplayX(disPlayX[j - 1]);
        itemFirst.SetDisplayY(disPlayY[j - 1]);
        itemFirst.SetPressed(1);
        pointerEvent->AddPointerItem(itemFirst);
    }
    InputManager::GetInstance()->SimulateTouchPadEvent(pointerEvent);
}

HWTEST_F(InputManagerInjectTest, TestSimulateTouchPadEvent_002, TestSize.Level1)
{
    int32_t disPlayX[3] = {0, 52, 81};
    int32_t disPlayY[3] = {0, 37, 46};
    int32_t fingerCount = 3;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(0);
    pointerEvent->SetOriginPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetFingerCount(fingerCount);
    pointerEvent->SetPointerId(fingerCount - 1);
    int64_t actionTimeBase = GetSysClockTime();
    pointerEvent->SetActionTime(actionTimeBase);
    pointerEvent->SetActionStartTime(actionTimeBase);
    PointerEvent::PointerItem item;
    item.SetDownTime(pointerEvent->GetActionStartTime());
    item.SetDisplayX(disPlayX[0]);
    item.SetDisplayY(disPlayY[0]);
    pointerEvent->AddPointerItem(item);
    for (int32_t j = 1; j < fingerCount; j++) {
        PointerEvent::PointerItem itemFirst;
        itemFirst.SetPointerId(j);
        itemFirst.SetDownTime(actionTimeBase);
        itemFirst.SetDisplayX(disPlayX[j - 1]);
        itemFirst.SetDisplayY(disPlayY[j - 1]);
        itemFirst.SetPressed(1);
        pointerEvent->AddPointerItem(itemFirst);
    }
    InputManager::GetInstance()->SimulateTouchPadEvent(pointerEvent);
}

HWTEST_F(InputManagerInjectTest, TestSimulateTouchPadEvent_003, TestSize.Level1)
{
    int32_t disPlayX[3] = {894, 52, 81};
    int32_t disPlayY[3] = {562, 33, 42};
    int32_t fingerCount = 3;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(0);
    pointerEvent->SetOriginPointerAction(PointerEvent::POINTER_ACTION_SWIPE_END);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_END);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetFingerCount(fingerCount);
    pointerEvent->SetPointerId(fingerCount - 1);
    int64_t actionTimeBase = GetSysClockTime();
    pointerEvent->SetActionTime(actionTimeBase);
    pointerEvent->SetActionStartTime(actionTimeBase);
    PointerEvent::PointerItem item;
    item.SetDownTime(pointerEvent->GetActionStartTime());
    item.SetDisplayX(disPlayX[0]);
    item.SetDisplayY(disPlayY[0]);
    pointerEvent->AddPointerItem(item);
    for (int32_t j = 1; j < fingerCount; j++) {
        PointerEvent::PointerItem itemFirst;
        itemFirst.SetPointerId(j);
        itemFirst.SetDownTime(actionTimeBase);
        itemFirst.SetDisplayX(disPlayX[j - 1]);
        itemFirst.SetDisplayY(disPlayY[j - 1]);
        itemFirst.SetPressed(1);
        pointerEvent->AddPointerItem(itemFirst);
    }
    InputManager::GetInstance()->SimulateTouchPadEvent(pointerEvent);
}

HWTEST_F(InputManagerInjectTest, TestSimulateTouchPadEvent_004, TestSize.Level1)
{
    int32_t fingerCount = 2;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(0);
    pointerEvent->SetOriginPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetFingerCount(fingerCount);
    pointerEvent->SetPointerId(fingerCount - 1);
    int64_t actionTimeBase = GetSysClockTime();
    pointerEvent->SetActionTime(actionTimeBase);
    pointerEvent->SetActionStartTime(actionTimeBase);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
    PointerEvent::PointerItem itemFirst;
    itemFirst.SetDownTime(actionTimeBase);
    itemFirst.SetDisplayX(135);
    itemFirst.SetDisplayY(105);
    itemFirst.SetWindowX(135);
    itemFirst.SetWindowY(105);
    itemFirst.SetToolType(0);
    pointerEvent->AddPointerItem(itemFirst);
    PointerEvent::PointerItem itemSecond;
    itemSecond.SetPointerId(1);
    itemSecond.SetDownTime(actionTimeBase);
    itemSecond.SetDisplayX(95);
    itemSecond.SetDisplayY(95);
    itemSecond.SetWindowX(85);
    itemSecond.SetWindowY(85);
    itemSecond.SetPressed(0);
    pointerEvent->AddPointerItem(itemSecond);
    InputManager::GetInstance()->SimulateTouchPadEvent(pointerEvent);
}

HWTEST_F(InputManagerInjectTest, TestSimulateTouchPadEvent_005, TestSize.Level1)
{
    int32_t fingerCount = 2;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(0);
    pointerEvent->SetOriginPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetFingerCount(fingerCount);
    pointerEvent->SetPointerId(fingerCount - 1);
    int64_t actionTimeBase = GetSysClockTime();
    pointerEvent->SetActionTime(actionTimeBase);
    pointerEvent->SetActionStartTime(actionTimeBase);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
    PointerEvent::PointerItem itemFirst;
    itemFirst.SetDownTime(actionTimeBase);
    itemFirst.SetDisplayX(125);
    itemFirst.SetDisplayY(100);
    itemFirst.SetWindowX(125);
    itemFirst.SetWindowY(100);
    itemFirst.SetToolType(0);
    pointerEvent->AddPointerItem(itemFirst);
    PointerEvent::PointerItem itemSecond;
    itemSecond.SetPointerId(1);
    itemSecond.SetDownTime(actionTimeBase);
    itemSecond.SetDisplayX(98);
    itemSecond.SetDisplayY(98);
    itemSecond.SetWindowX(89);
    itemSecond.SetWindowY(89);
    itemSecond.SetPressed(0);
    pointerEvent->AddPointerItem(itemSecond);
    InputManager::GetInstance()->SimulateTouchPadEvent(pointerEvent);
}
} // namespace MMI
} // namespace OHOS
