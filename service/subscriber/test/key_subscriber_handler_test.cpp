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

#include <fstream>
#include <list>

#include <gtest/gtest.h>

#include "key_option.h"
#include "key_subscriber_handler.h"
#include "call_manager_client.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_event_monitor.h"
#include "input_event_handler.h"
#include "key_event.h"
#include "mmi_log.h"
#include "nap_process.h"
#include "switch_subscriber_handler.h"
#include "uds_server.h"
#include "want.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string PROGRAM_NAME = "uds_session_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = 1;
constexpr int32_t UDS_UID = 100;
constexpr int32_t UDS_PID = 100;
constexpr int32_t REMOVE_OBSERVER { -2 };
constexpr int32_t UNOBSERVED { -1 };
constexpr int32_t ACTIVE_EVENT { 2 };
} // namespace

class KeySubscriberHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputWindowsManagerTest_UnsubscribeKeyEvent_001
 * @tc.desc: Test UnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, InputWindowsManagerTest_UnsubscribeKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keySubscriberHandler.HandleKeyEvent(keyEvent);
    auto pointerEvent = PointerEvent::Create();
    keySubscriberHandler.HandlePointerEvent(pointerEvent);
    keySubscriberHandler.HandleTouchEvent(pointerEvent);
    keySubscriberHandler.RemoveSubscriberKeyUpTimer(1);
    std::vector<std::string> args = {};
    keySubscriberHandler.Dump(1, args);
    UDSServer udsServer;
    SessionPtr sess = udsServer.GetSessionByPid(1);
    std::shared_ptr<KeyOption> keyOption = nullptr;
    ASSERT_EQ(keySubscriberHandler.SubscribeKeyEvent(sess, -1, keyOption), -1);
    SessionPtr sessPtr = nullptr;
    ASSERT_NE(keySubscriberHandler.UnsubscribeKeyEvent(sessPtr, -1), 0);
    ASSERT_NE(keySubscriberHandler.UnsubscribeKeyEvent(sess, 1), 0);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_001
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    keySubscriberHandler.EnableCombineKey(false);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keySubscriberHandler.HandleKeyEvent(keyEvent);
    ASSERT_EQ(keySubscriberHandler.EnableCombineKey(true), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_002
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    keySubscriberHandler.EnableCombineKey(false);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_L);
    keyEvent->AddKeyItem(item2);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_L);
    ASSERT_EQ(keySubscriberHandler.EnableCombineKey(true), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_EnableCombineKey_001
 * @tc.desc: Test enable combineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_EnableCombineKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    ASSERT_EQ(keySubscriberHandler.EnableCombineKey(true), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscribeKeyEvent_001
 * @tc.desc: Test subscribe keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscribeKeyEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    SessionPtr sess;
    auto keyOption = std::make_shared<KeyOption>();
    int32_t ret = handler.SubscribeKeyEvent(sess, -1, keyOption);
    ASSERT_EQ(ret, RET_ERR);
    ret = handler.SubscribeKeyEvent(nullptr, 1, keyOption);
    ASSERT_NE(ret, RET_OK);
    ret = handler.SubscribeKeyEvent(sess, 1, keyOption);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriber_001
 * @tc.desc: Test remove subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriber_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    SessionPtr sess;
    int32_t ret = handler.RemoveSubscriber(sess, 1);
    ASSERT_EQ(ret, RET_ERR);
    ret = handler.RemoveSubscriber(nullptr, 1);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEqualKeyOption_001
 * @tc.desc: Test is equal keyOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEqualKeyOption_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto newOption = std::make_shared<KeyOption>();
    auto oldOption = std::make_shared<KeyOption>();
    newOption->SetPreKeys({1, 2, 3});
    oldOption->SetPreKeys({4, 5, 6});
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    newOption->SetFinalKey(1);
    oldOption->SetFinalKey(2);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    newOption->SetFinalKeyDown(true);
    oldOption->SetFinalKeyDown(false);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    newOption->SetFinalKeyDownDuration(100);
    oldOption->SetFinalKeyDownDuration(200);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    newOption->SetFinalKeyUpDelay(100);
    oldOption->SetFinalKeyUpDelay(200);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    newOption->SetPreKeys({1, 2, 3});
    oldOption->SetPreKeys({1, 2, 3});
    newOption->SetFinalKey(1);
    oldOption->SetFinalKey(1);
    newOption->SetFinalKeyDown(true);
    oldOption->SetFinalKeyDown(true);
    newOption->SetFinalKeyDownDuration(100);
    oldOption->SetFinalKeyDownDuration(100);
    newOption->SetFinalKeyUpDelay(100);
    oldOption->SetFinalKeyUpDelay(100);
    ASSERT_TRUE(handler.IsEqualKeyOption(newOption, oldOption));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsPreKeysMatch_001
 * @tc.desc: Test is preKeys match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsPreKeysMatch_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::set<int32_t> preKeys;
    std::vector<int32_t> pressedKeys = {1, 2, 3};
    ASSERT_TRUE(handler.IsPreKeysMatch(preKeys, pressedKeys));
    preKeys = {1, 2, 3};
    ASSERT_TRUE(handler.IsPreKeysMatch(preKeys, pressedKeys));
    pressedKeys = {1, 2, 3, 4};
    ASSERT_FALSE(handler.IsPreKeysMatch(preKeys, pressedKeys));
    pressedKeys = {1, 2, 3};
    preKeys = {1, 2, 3, 4};
    ASSERT_FALSE(handler.IsPreKeysMatch(preKeys, pressedKeys));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEqualPreKeys_001
 * @tc.desc: Test is equal preKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEqualPreKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::set<int32_t> preKeys = {1, 2, 3};
    std::set<int32_t> pressedKeys = {4, 5, 6};
    ASSERT_FALSE(handler.IsEqualPreKeys(preKeys, pressedKeys));
    pressedKeys = {1, 2, 3};
    ASSERT_TRUE(handler.IsEqualPreKeys(preKeys, pressedKeys));
    pressedKeys = {1, 2};
    ASSERT_FALSE(handler.IsEqualPreKeys(preKeys, pressedKeys));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsMatchForegroundPid_001
 * @tc.desc: Test is match foreground pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsMatchForegroundPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subs;
    std::set<int32_t> foregroundPids = {1, 2, 3};
    ASSERT_FALSE(handler.IsMatchForegroundPid(subs, foregroundPids));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownSubscriber_001
 * @tc.desc: Test notify key down subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    auto keyOption = std::make_shared<KeyOption>();
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownSubscriber(keyEvent, keyOption, subscribers, handled));
    keyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownSubscriber(keyEvent, keyOption, subscribers, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownRightNow_001
 * @tc.desc: Test notify key down right now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownRightNow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    handler.NotifyKeyDownRightNow(keyEvent, subscribers, handled);
    ASSERT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_001
 * @tc.desc: Test notify key down delay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    handler.NotifyKeyDownDelay(keyEvent, subscribers, handled);
    ASSERT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ClearTimer_001
 * @tc.desc: Test clear timer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ClearTimer_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscriber->timerId_ = -1;
    handler.ClearTimer(subscriber);
    ASSERT_EQ(subscriber->timerId_, -1);
    subscriber->timerId_ = 1;
    handler.ClearTimer(subscriber);
    ASSERT_EQ(subscriber->timerId_, -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_InitSessionDeleteCallback_001
 * @tc.desc: Test init session delete callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_InitSessionDeleteCallback_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    handler.callbackInitialized_ = true;
    ASSERT_TRUE(handler.InitSessionDeleteCallback());
    handler.callbackInitialized_ = false;
    ASSERT_FALSE(handler.InitSessionDeleteCallback());
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_001
 * @tc.desc: Test handle key down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto result = handler.HandleKeyDown(nullptr);
    ASSERT_FALSE(result);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    result = handler.HandleKeyDown(keyEvent);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveKeyCode_001
 * @tc.desc: Test remove key code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveKeyCode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::vector<int32_t> keyCodes;
    handler.RemoveKeyCode(1, keyCodes);
    ASSERT_TRUE(keyCodes.empty());
    keyCodes = {2, 3, 4};
    handler.RemoveKeyCode(1, keyCodes);
    ASSERT_EQ(keyCodes, (std::vector<int32_t>{2, 3, 4}));
    keyCodes = {1, 2, 3};
    ASSERT_EQ(keyCodes, (std::vector<int32_t>{1, 2, 3}));
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddSubscriber_001
 * @tc.desc: Test add subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::shared_ptr<KeyOption> option = std::make_shared<KeyOption>();
    handler.AddSubscriber(subscriber, option);
    auto it = handler.subscriberMap_.find(option);
    ASSERT_NE(it, handler.subscriberMap_.end());
    ASSERT_EQ(it->second.size(), 1);
    ASSERT_EQ(it->second.front(), subscriber);
    auto newSubscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    handler.AddSubscriber(newSubscriber, option);
    ASSERT_EQ(it->second.size(), 2);
    ASSERT_EQ(it->second.back(), newSubscriber);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsFunctionKey_001
 * @tc.desc: Test is function key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsFunctionKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
    keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_UP);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
    keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_MUTE);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
    keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_SWITCHVIDEOMODE);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
    keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_WLAN);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
    keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_CONFIG);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
    keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_A);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_CloneKeyEvent_001
 * @tc.desc: Test clone key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_CloneKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_TRUE(handler.CloneKeyEvent(keyEvent));
    handler.keyEvent_ = nullptr;
    ASSERT_TRUE(handler.CloneKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyUpSubscriber_001
 * @tc.desc: Test notify key up subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyUpSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
    ASSERT_FALSE(handled);
    handler.isForegroundExits_ = false;
    handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
    ASSERT_FALSE(handled);
    handler.isForegroundExits_ = true;
    handler.foregroundPids_.clear();
    handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
    ASSERT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKeySwipe_001
 * @tc.desc: Test is enable combine key swipe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKeySwipe_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    ASSERT_TRUE(handler.IsEnableCombineKeySwipe(keyEvent));
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    ASSERT_TRUE(handler.IsEnableCombineKeySwipe(keyEvent));
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    ASSERT_TRUE(handler.IsEnableCombineKeySwipe(keyEvent));
    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    ASSERT_TRUE(handler.IsEnableCombineKeySwipe(keyEvent));
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    ASSERT_TRUE(handler.IsEnableCombineKeySwipe(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_001
 * @tc.desc: Test on subscribe key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSubscribeKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler.OnSubscribeKeyEvent(keyEvent);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSessionDelete_001
 * @tc.desc: Test onSession delete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSessionDelete_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    UDSServer udsServer;
    auto keyOption = std::make_shared<KeyOption>();
    SessionPtr sess = udsServer.GetSessionByPid(1);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>>subscriberMap_;
    auto newSubscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    auto newSubscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    auto newSubscriber3 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(3, sess, keyOption);
    subscriberMap_.push_back(newSubscriber1);
    subscriberMap_.push_back(newSubscriber2);
    subscriberMap_.push_back(newSubscriber3);
    handler.OnSessionDelete(sess);
    for (auto& sub : subscriberMap_) {
        ASSERT_EQ(sub->sess_, nullptr);
    }
}

/**
 * @tc.name: KeySubscriberHandlerTest_ClearSubscriberTimer_001
 * @tc.desc: Test clear subscriber timer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ClearSubscriberTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    auto subscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    auto subscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    ASSERT_NO_FATAL_FAILURE(handler.ClearSubscriberTimer(subscribers));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnTimer_001
 * @tc.desc: Test OnTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscriber->keyEvent_.reset();
    handler.OnTimer(subscriber);
    ASSERT_EQ(subscriber->keyEvent_, nullptr);
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscriberNotifyNap_001
 * @tc.desc: Test SubscriberNotifyNap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscriberNotifyNap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_001
 * @tc.desc: Test HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    bool handled = handler.HandleKeyUp(keyEvent);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_001
 * @tc.desc: Test NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyCancel_001
 * @tc.desc: Test HandleKeyCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyCancel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    UDSServer udsServer;
    SessionPtr sess = udsServer.GetSessionByPid(1);
    auto keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>>subscriberMap_;
    auto newSubscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    auto newSubscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    subscriberMap_.push_back(newSubscriber1);
    subscriberMap_.push_back(newSubscriber2);
    EXPECT_FALSE(handler.HandleKeyCancel(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsNotifyPowerKeySubsciber_001
 * @tc.desc: Test IsNotifyPowerKeySubsciber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsNotifyPowerKeySubsciber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::vector<int32_t> keyCodes = {KeyEvent::KEYCODE_VOLUME_DOWN};
    EXPECT_TRUE(handler.IsNotifyPowerKeySubsciber(KeyEvent::KEYCODE_VOLUME_DOWN, keyCodes));
    keyCodes = {KeyEvent::KEYCODE_POWER, KeyEvent::KEYCODE_VOLUME_DOWN};
    EXPECT_FALSE(handler.IsNotifyPowerKeySubsciber(KeyEvent::KEYCODE_POWER, keyCodes));
    keyCodes = {KeyEvent::KEYCODE_POWER};
    EXPECT_TRUE(handler.IsNotifyPowerKeySubsciber(KeyEvent::KEYCODE_POWER, keyCodes));
}

/**
 * @tc.name: KeySubscriberHandlerTest_PrintKeyOption_001
 * @tc.desc: Test PrintKeyOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_PrintKeyOption_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(1);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(1000);
    keyOption->SetPreKeys({1, 2, 3});
    ASSERT_NO_FATAL_FAILURE(handler.PrintKeyOption(keyOption));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDelay_001
 * @tc.desc: Test HandleKeyUpWithDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    auto keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    keyOption->SetFinalKeyUpDelay(0);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyUpWithDelay(keyEvent, subscriber));
    keyOption->SetFinalKeyUpDelay(-1);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyUpWithDelay(keyEvent, subscriber));
    keyOption->SetFinalKeyUpDelay(1);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyUpWithDelay(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_001
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_002
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_003
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_004
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_F1);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_005
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_006
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_007
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_008
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_009
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscribeKeyEvent_002
 * @tc.desc: Test subscribe keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscribeKeyEvent_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::set<int32_t> preKeys;
    preKeys.insert(1);
    keyOption->SetPreKeys(preKeys);
    ASSERT_EQ(handler.SubscribeKeyEvent(sess, subscribeId, keyOption), RET_OK);

    preKeys.insert(2);
    preKeys.insert(3);
    preKeys.insert(4);
    preKeys.insert(5);
    preKeys.insert(6);
    keyOption->SetPreKeys(preKeys);
    ASSERT_EQ(handler.SubscribeKeyEvent(sess, subscribeId, keyOption), RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEqualKeyOption
 * @tc.desc: Test Is Equal KeyOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEqualKeyOption, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyOption> newOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeyOption> oldOption = std::make_shared<KeyOption>();
    std::set<int32_t> preKeys;
    std::set<int32_t> pressedKeys;
    preKeys.insert(1);
    pressedKeys.insert(1);
    newOption->SetPreKeys(preKeys);
    oldOption->SetPreKeys(pressedKeys);
    newOption->SetFinalKey(1);
    oldOption->SetFinalKey(2);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));

    oldOption->SetFinalKey(1);
    newOption->SetFinalKeyDown(true);
    oldOption->SetFinalKeyDown(false);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    oldOption->SetFinalKeyDown(true);

    newOption->SetFinalKeyDownDuration(100);
    oldOption->SetFinalKeyDownDuration(150);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    oldOption->SetFinalKeyDownDuration(100);

    newOption->SetFinalKeyUpDelay(100);
    oldOption->SetFinalKeyUpDelay(150);
    ASSERT_FALSE(handler.IsEqualKeyOption(newOption, oldOption));
    oldOption->SetFinalKeyUpDelay(100);
    ASSERT_TRUE(handler.IsEqualKeyOption(newOption, oldOption));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_003
 * @tc.desc: Test Is Enable CombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    KeyEvent::KeyItem item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    handler.enableCombineKey_ = false;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    ASSERT_TRUE(handler.IsEnableCombineKey(keyEvent));

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_TRUE(handler.IsEnableCombineKey(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->AddKeyItem(item);
    ASSERT_FALSE(handler.IsEnableCombineKey(keyEvent));

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    ASSERT_FALSE(handler.IsEnableCombineKey(keyEvent));

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_L);
    ASSERT_FALSE(handler.IsEnableCombineKey(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_004
 * @tc.desc: Test Is Enable CombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    KeyEvent::KeyItem item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.enableCombineKey_ = false;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_L);
    item.SetKeyCode(KeyEvent::KEYCODE_L);
    keyEvent->AddKeyItem(item);
    ASSERT_TRUE(handler.IsEnableCombineKey(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_005
 * @tc.desc: Test Is Enable CombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    KeyEvent::KeyItem item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.enableCombineKey_ = false;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_L);
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    ASSERT_TRUE(handler.IsEnableCombineKey(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_006
 * @tc.desc: Test Is Enable CombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    KeyEvent::KeyItem item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.enableCombineKey_ = false;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_L);
    item.SetKeyCode(KeyEvent::KEYCODE_META_RIGHT);
    keyEvent->AddKeyItem(item);
    ASSERT_TRUE(handler.IsEnableCombineKey(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriber
 * @tc.desc: Test Remove Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriber, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 2;
    int32_t id = 1;
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    subscriberList.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscriberList));
    ASSERT_EQ(handler.RemoveSubscriber(session, subscribeId), RET_ERR);
    subscribeId = 1;
    ASSERT_EQ(handler.RemoveSubscriber(session, subscribeId), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsFunctionKey
 * @tc.desc: Test IsFunctionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsFunctionKey, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BRIGHTNESS_UP);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_MUTE);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_MUTE);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_SWITCHVIDEOMODE);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_WLAN);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CONFIG);
    ASSERT_TRUE(handler.IsFunctionKey(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent
 * @tc.desc: Test OnSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSubscribeKeyEvent, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    KeyEvent::KeyItem item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.enableCombineKey_ = false;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->AddKeyItem(item);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));

    handler.enableCombineKey_ = true;
    handler.hasEventExecuting_ = true;
    handler.keyEvent_ = KeyEvent::Create();
    ASSERT_NE(handler.keyEvent_, nullptr);
    handler.keyEvent_->SetKeyCode(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    handler.keyEvent_->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    handler.keyEvent_->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    handler.keyEvent_->AddKeyItem(item);
    ASSERT_TRUE(handler.OnSubscribeKeyEvent(keyEvent));

    handler.hasEventExecuting_ = false;
    handler.needSkipPowerKeyUp_ = true;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_TRUE(handler.OnSubscribeKeyEvent(keyEvent));

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSessionDelete
 * @tc.desc: Test OnSessionDelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSessionDelete, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t id = 1;
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    subscriberList.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscriberList));
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NO_FATAL_FAILURE(handler.OnSessionDelete(sess));
    ASSERT_NO_FATAL_FAILURE(handler.OnSessionDelete(session));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsPreKeysMatch
 * @tc.desc: Test IsPreKeysMatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsPreKeysMatch, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::set<int32_t> preKeys;
    std::vector<int32_t> pressedKeys;
    preKeys.insert(KeyEvent::KEYCODE_A);
    pressedKeys.push_back(KeyEvent::KEYCODE_B);
    ASSERT_FALSE(handler.IsPreKeysMatch(preKeys, pressedKeys));
    preKeys.clear();
    pressedKeys.clear();
    preKeys.insert(KeyEvent::KEYCODE_C);
    pressedKeys.push_back(KeyEvent::KEYCODE_C);
    ASSERT_TRUE(handler.IsPreKeysMatch(preKeys, pressedKeys));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsMatchForegroundPid
 * @tc.desc: Test Is Match Foreground Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsMatchForegroundPid, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t id = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    std::set<int32_t> foregroundPids;
    subscriberList.push_back(subscriber);
    foregroundPids.insert(1);
    ASSERT_FALSE(handler.IsMatchForegroundPid(subscriberList, foregroundPids));

    foregroundPids.insert(100);
    ASSERT_TRUE(handler.IsMatchForegroundPid(subscriberList, foregroundPids));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownSubscriber
 * @tc.desc: Test Notify Key Down Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownSubscriber, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t id = 1;
    bool handled = false;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    subscriberList.push_back(subscriber);
    keyOption->SetFinalKeyDownDuration(100);
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownSubscriber(keyEvent, keyOption, subscriberList, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownRightNow
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownRightNow, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t id = 1;
    bool handled = false;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    subscriberList.push_back(subscriber);
    handler.isForegroundExits_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownRightNow(keyEvent, subscriberList, handled));

    handler.isForegroundExits_ = false;
    handler.foregroundPids_.insert(UDS_PID);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownRightNow(keyEvent, subscriberList, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay
 * @tc.desc: Test Notify KeyDown Delay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t id = 1;
    bool handled = false;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    subscriber->timerId_ = 1;
    subscriberList.push_back(subscriber);
    handler.isForegroundExits_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownDelay(keyEvent, subscriberList, handled));

    handler.isForegroundExits_ = false;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    handler.foregroundPids_.insert(UDS_PID);
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownDelay(keyEvent, subscriberList, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyUpSubscriber
 * @tc.desc: Test Notify KeyUp Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyUpSubscriber, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t id = 1;
    bool handled = false;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    subscriber->timerId_ = 1;
    keyOption->SetFinalKeyUpDelay(1000);
    subscriberList.push_back(subscriber);
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyUpSubscriber(keyEvent, subscriberList, handled));
    handler.isForegroundExits_ = true;
    handler.foregroundPids_.insert(UDS_PID);
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyUpSubscriber(keyEvent, subscriberList, handled));
    handler.foregroundPids_.erase(UDS_PID);
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyUpSubscriber(keyEvent, subscriberList, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnTimer
 * @tc.desc: Test OnTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnTimer, TestSize.Level1)
{
    KeySubscriberHandler handler;
    int32_t id = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    ASSERT_EQ(subscriber->keyEvent_, nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.OnTimer(subscriber));
    subscriber->keyEvent_ = KeyEvent::Create();
    ASSERT_NE(subscriber->keyEvent_, nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.OnTimer(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsKeyEventSubscribed
 * @tc.desc: Test IsKeyEventSubscribed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsKeyEventSubscribed, TestSize.Level1)
{
    KeySubscriberHandler handler;
    int32_t id = 1;
    int32_t keyCode = KeyEvent::KEYCODE_ALT_LEFT;
    int32_t trrigerType = KeyEvent::KEY_ACTION_DOWN;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDown(false);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_CTRL_LEFT);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    subscriberList.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscriberList));
    ASSERT_FALSE(handler.IsKeyEventSubscribed(keyCode, trrigerType));

    for (auto &iter : handler.subscriberMap_) {
        iter.first->SetFinalKeyDown(true);
    }
    keyCode = KeyEvent::KEYCODE_CTRL_LEFT;
    ASSERT_TRUE(handler.IsKeyEventSubscribed(keyCode, trrigerType));
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveKeyCode
 * @tc.desc: Test RemoveKeyCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveKeyCode, TestSize.Level1)
{
    KeySubscriberHandler handler;
    int32_t keyCode = KeyEvent::KEYCODE_A;
    std::vector<int32_t> keyCodes { KeyEvent::KEYCODE_A, KeyEvent::KEYCODE_B };
    ASSERT_NO_FATAL_FAILURE(handler.RemoveKeyCode(keyCode, keyCodes));
    keyCode = KeyEvent::KEYCODE_C;
    ASSERT_NO_FATAL_FAILURE(handler.RemoveKeyCode(keyCode, keyCodes));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsRepeatedKeyEvent
 * @tc.desc: Test IsRepeatedKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsRepeatedKeyEvent, TestSize.Level1)
{
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_FALSE(handler.IsRepeatedKeyEvent(keyEvent));
    handler.keyEvent_ = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.hasEventExecuting_ = true;
    handler.keyEvent_->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_B);
    ASSERT_FALSE(handler.IsRepeatedKeyEvent(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    handler.keyEvent_->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_FALSE(handler.IsRepeatedKeyEvent(keyEvent));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    handler.keyEvent_->AddKeyItem(item);
    ASSERT_FALSE(handler.IsRepeatedKeyEvent(keyEvent));
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->AddKeyItem(item);
    ASSERT_FALSE(handler.IsRepeatedKeyEvent(keyEvent));
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    handler.keyEvent_->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_D);
    keyEvent->AddKeyItem(item);
    ASSERT_FALSE(handler.IsRepeatedKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberKeyUpTimer
 * @tc.desc: Test RemoveSubscriberKeyUpTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberKeyUpTimer, TestSize.Level1)
{
    KeySubscriberHandler handler;
    int32_t keyCode = KeyEvent::KEYCODE_A;
    int32_t id = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    subscriber->timerId_ = -1;
    subscriberList.push_back(subscriber);
    subscriber->timerId_ = 1;
    subscriber->keyOption_->SetFinalKey(KeyEvent::KEYCODE_A);
    subscriberList.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscriberList));
    ASSERT_NO_FATAL_FAILURE(handler.RemoveSubscriberKeyUpTimer(keyCode));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsNotifyPowerKeySubsciber
 * @tc.desc: Test IsNotifyPowerKeySubsciber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsNotifyPowerKeySubsciber, TestSize.Level1)
{
    KeySubscriberHandler handler;
    int32_t keyCode = KeyEvent::KEYCODE_A;
    std::vector<int32_t> keyCodes;
    ASSERT_TRUE(handler.IsNotifyPowerKeySubsciber(keyCode, keyCodes));
    keyCode = KeyEvent::KEYCODE_POWER;
    keyCodes.push_back(KeyEvent::KEYCODE_A);
    ASSERT_TRUE(handler.IsNotifyPowerKeySubsciber(keyCode, keyCodes));
    keyCodes.insert(keyCodes.begin(), KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_FALSE(handler.IsNotifyPowerKeySubsciber(keyCode, keyCodes));
    keyCodes.insert(keyCodes.begin(), KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_FALSE(handler.IsNotifyPowerKeySubsciber(keyCode, keyCodes));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_010
 * @tc.desc: Test the funcation HandleRingMute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int32_t callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    DeviceEventMonitor monitor;
    monitor.hasHandleRingMute_ = false;
    bool ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
    monitor.hasHandleRingMute_ = true;
    ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
    want.SetParam("state", StateType::CALL_STATUS_ALERTING);
    data.SetWant(want);
    DEVICE_MONITOR->SetCallState(data, callState);
    ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_002
 * @tc.desc: Test the funcation OnSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSubscribeKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    bool ret = handler.OnSubscribeKeyEvent(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_003
 * @tc.desc: Test the funcation OnSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSubscribeKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.needSkipPowerKeyUp_ = true;
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_TRUE(handler.OnSubscribeKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_002
 * @tc.desc: Test the funcation NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddTimer_001
 * @tc.desc: Test the funcation AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t id = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    subscriber->timerId_ = 1;
    bool ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
    subscriber->timerId_ = -1;
    keyOption->isFinalKeyDown_ = true;
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
    keyOption->isFinalKeyDown_ = false;
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_002
 * @tc.desc: Test the funcation HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = false;
    SessionPtr sess;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    bool ret = handler.HandleKeyDown(keyEvent);
    ASSERT_FALSE(ret);
    keyOption->isFinalKeyDown_ = true;
    keyOption->finalKey_ = true;
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ret = handler.HandleKeyDown(keyEvent);
    ASSERT_FALSE(ret);
    keyOption->finalKey_ = false;
    std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    ret = handler.HandleKeyDown(keyEvent);
    ASSERT_FALSE(ret);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    ret = handler.HandleKeyDown(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_002
 * @tc.desc: Test the funcation HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = true;
    SessionPtr sess;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    bool ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    keyOption->isFinalKeyDown_ = false;
    keyOption->finalKey_ = -1;
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    keyOption->finalKey_ = 0;
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    std::set<int32_t> preKeys;
    std::vector<int32_t> pressedKeys = {1, 2, 3};
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    pressedKeys = {1, 2, 3};
    preKeys = {1, 2, 3, 4};
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_01
 * @tc.desc: Test the funcation HandleRingMute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    DeviceEventMonitor monitor;
    monitor.callState_ = StateType::CALL_STATUS_INCOMING;
    bool ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
    handler.HandleRingMute(keyEvent);
    monitor.hasHandleRingMute_ = false;
    ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
    monitor.hasHandleRingMute_ = true;
    ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
    monitor.callState_ = StateType::CALL_STATUS_DIALING;
    ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_02
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    auto callManagerClientPtr = DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
    callManagerClientPtr = nullptr;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_03
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    auto callManagerClientPtr = DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    auto ret = callManagerClientPtr->MuteRinger();
    EXPECT_NE(ret, ERR_OK);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_04
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    auto callManagerClientPtr = DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    keyEvent->keyCode_ = KeyEvent::KEYCODE_POWER;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_05
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    auto callManagerClientPtr = DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    keyEvent->keyCode_ = KeyEvent::KEYCODE_CALL;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_06
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_UP;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    auto callManagerClientPtr = DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    keyEvent->keyCode_ = KeyEvent::KEYCODE_POWER;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_07
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_UP;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    auto callManagerClientPtr = DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    keyEvent->keyCode_ = KeyEvent::KEYCODE_CAMERA;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_004
 * @tc.desc: Test the funcation OnSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSubscribeKeyEvent_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    KeyEvent::KeyItem item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.enableCombineKey_ = false;
    keyEvent->SetKeyCode(KeyEvent::KEY_ACTION_UP);
    item.SetKeyCode(KeyEvent::KEYCODE_O);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_P);
    keyEvent->AddKeyItem(item);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
    handler.enableCombineKey_ = true;
    handler.hasEventExecuting_ = true;
    handler.keyEvent_ = KeyEvent::Create();
    ASSERT_NE(handler.keyEvent_, nullptr);
    handler.keyEvent_->SetKeyCode(KeyEvent::KEY_ACTION_UP);
    handler.keyEvent_->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_O);
    handler.keyEvent_->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_P);
    handler.keyEvent_->AddKeyItem(item);
    ASSERT_TRUE(handler.OnSubscribeKeyEvent(keyEvent));
    handler.hasEventExecuting_ = false;
    handler.needSkipPowerKeyUp_ = true;
    keyEvent->SetKeyCode(KeyEvent::KEY_ACTION_CANCEL);
    ASSERT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_003
 * @tc.desc: Test the funcation NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
    item.SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_004
 * @tc.desc: Test NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    ASSERT_NE(subscriber, nullptr);

    keyEvent->keyCode_ = KeyEvent::KEYCODE_POWER;
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddTimer_002
 * @tc.desc: Test the funcation AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddTimer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t id = 3;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    subscriber->timerId_ = 5;
    bool ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
    subscriber->timerId_ = -5;
    keyOption->isFinalKeyDown_ = true;
    keyOption->finalKeyDownDuration_ = -5;
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
    keyOption->finalKeyDownDuration_ = 5;
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
    keyOption->isFinalKeyDown_ = false;
    keyOption->finalKeyUpDelay_ = -5;
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
    keyOption->finalKeyUpDelay_ = 5;
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_003
 * @tc.desc: Test the funcation HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = true;
    keyEvent->keyCode_ = 1;
    SessionPtr sess;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    keyOption->finalKey_ = 5;
    bool ret = handler.HandleKeyDown(keyEvent);
    ASSERT_FALSE(ret);
    keyOption->finalKey_ = 1;
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    ret = handler.HandleKeyDown(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscriberNotifyNap_002
 * @tc.desc: Test the funcation SubscriberNotifyNap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscriberNotifyNap_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    NapProcess napProcess;
    napProcess.napClientPid_ = REMOVE_OBSERVER;
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
    napProcess.napClientPid_ = UNOBSERVED;
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
    napProcess.napClientPid_ = 10;
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscriberNotifyNap_003
 * @tc.desc: Test the funcation SubscriberNotifyNap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscriberNotifyNap_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    ASSERT_NE(subscriber, nullptr);

    NapProcess napProcess;
    napProcess.napClientPid_ = ACTIVE_EVENT;
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = 2;
    napData.uid = 3;
    napData.bundleName = "programName";
    EXPECT_FALSE(napProcess.IsNeedNotify(napData));
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
}
} // namespace MMI
} // namespace OHOS
