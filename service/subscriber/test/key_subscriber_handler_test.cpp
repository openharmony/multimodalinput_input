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
#include "key_shortcut_manager.h"
#ifdef OHOS_BUILD_ENABLE_CALL_MANAGER
#include "call_manager_client.h"
#endif // OHOS_BUILD_ENABLE_CALL_MANAGER
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_event_monitor.h"
#include "display_event_monitor.h"
#include "input_event_handler.h"
#include "key_event.h"
#include "mmi_log.h"
#include "nap_process.h"
#include "switch_subscriber_handler.h"
#ifdef OHOS_BUILD_ENABLE_PEN
#include "tablet_subscriber_handler.h"
#endif // OHOS_BUILD_ENABLE_PEN
#include "uds_server.h"
#include "want.h"
#include "event_log_helper.h"

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
constexpr uint32_t MAX_PRE_KEY_COUNT { 4 };
} // namespace

class KeySubscriberHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyEvent_001
 * @tc.desc: Test HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyEvent_001, TestSize.Level1)
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
    EXPECT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));

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
    EXPECT_TRUE(handler.OnSubscribeKeyEvent(keyEvent));
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_DumpSubscriber_001
 * @tc.desc: Test DumpSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_DumpSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t fd = 1;
    SessionPtr sess;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->preKeys_.insert(10);
    keyOption->preKeys_.insert(20);
    keyOption->preKeys_.insert(30);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    ASSERT_NO_FATAL_FAILURE(handler.DumpSubscriber(fd, subscriber));
}

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
    int32_t ret = handler.RemoveSubscriber(sess, 1, true);
    ASSERT_EQ(ret, RET_ERR);
    ret = handler.RemoveSubscriber(nullptr, 1, true);
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
    handler.NotifyKeyDownRightNow(keyEvent, subscribers, true, handled);
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

#ifdef OHOS_BUILD_ENABLE_CALL_MANAGER
/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDelay_002
 * @tc.desc: Test HandleKeyUpWithDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDelay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    auto keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);

    subscriber->keyOption_->finalKeyUpDelay_ = -2;
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
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}


HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_010
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleVoipRingMute_001
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleVoipRingMute_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_F1);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleVoipRingMute_003
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleVoipRingMute_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_013
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_014
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_015
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_016
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}
#endif // OHOS_BUILD_ENABLE_CALL_MANAGER

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
    ASSERT_NE(handler.SubscribeKeyEvent(sess, subscribeId, keyOption), RET_OK);

    preKeys.insert(2);
    preKeys.insert(3);
    preKeys.insert(4);
    preKeys.insert(5);
    preKeys.insert(6);
    keyOption->SetPreKeys(preKeys);
    ASSERT_NE(handler.SubscribeKeyEvent(sess, subscribeId, keyOption), RET_OK);
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
    ASSERT_EQ(handler.RemoveSubscriber(session, subscribeId, true), RET_ERR);
    subscribeId = 1;
    ASSERT_EQ(handler.RemoveSubscriber(session, subscribeId, true), RET_OK);
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
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CONFIG);
    ASSERT_FALSE(handler.IsFunctionKey(keyEvent));
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
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownRightNow(keyEvent, subscriberList, true, handled));

    handler.isForegroundExits_ = false;
    handler.foregroundPids_.insert(UDS_PID);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownRightNow(keyEvent, subscriberList, true, handled));
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

#ifdef OHOS_BUILD_ENABLE_CALL_MANAGER
/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_017
 * @tc.desc: Test the function HandleRingMute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_017, TestSize.Level1)
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
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_018
 * @tc.desc: Test the function HandleRingMute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_018, TestSize.Level1)
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
    DEVICE_MONITOR->SetVoipCallState(data, callState);
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
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    ret = handler.HandleRingMute(keyEvent);
    ASSERT_FALSE(ret);
}

#endif // OHOS_BUILD_ENABLE_CALL_MANAGER

/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_002
 * @tc.desc: Test the function OnSubscribeKeyEvent
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
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_005
 * @tc.desc: Test the function OnSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSubscribeKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_DISCONNECTED);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    data.SetWant(want);
    callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    bool ret = handler.OnSubscribeKeyEvent(keyEvent);
    ASSERT_FALSE(ret);
}


/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_003
 * @tc.desc: Test the function OnSubscribeKeyEvent
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
 * @tc.desc: Test the function NotifySubscriber
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
 * @tc.desc: Test the function AddTimer
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
 * @tc.desc: Test the function HandleKeyDown
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
 * @tc.desc: Test the function HandleKeyUp
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
    keyOption->finalKey_ = 2;
    std::set<int32_t> tmp;
    for (auto i = 0; i < 5; i++) {
        tmp.insert(i);
        KeyEvent::KeyItem keyItem;
        keyItem.pressed_ = true;
        keyItem.SetKeyCode(i);
        keyItem.downTime_ = 2000;
        keyEvent->keys_.push_back(keyItem);
    }
    tmp.clear();
    keyOption->SetPreKeys(tmp);
    keyOption->finalKeyDownDuration_ = 0;
    keyOption->finalKey_ = -1;
    keyEvent->SetKeyCode(-1);
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    KEY_SHORTCUT_MGR->isCheckShortcut_ = true;
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    keyOption->finalKeyDownDuration_ = 3;
    keyOption->finalKey_ = 3;
    keyEvent->SetKeyCode(3);
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    KEY_SHORTCUT_MGR->isCheckShortcut_ = true;
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_003
 * @tc.desc: Test the function HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_003, TestSize.Level1)
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
    keyOption->finalKey_ = 0;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    KEY_SHORTCUT_MGR->isCheckShortcut_ = true;
    keyEvent->SetKeyCode(-1);
    bool ret = false;
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    keyOption->finalKey_ = 2;
    std::set<int32_t> tmp;
    for (auto i = 0; i < 5; i++) {
        tmp.insert(i);
        KeyEvent::KeyItem keyItem;
        keyItem.pressed_ = true;
        keyItem.SetKeyCode(i);
        keyItem.downTime_ = 2000;
        keyEvent->keys_.push_back(keyItem);
    }
    keyOption->SetPreKeys(tmp);
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    keyEvent->SetKeyCode(2);
    KEY_SHORTCUT_MGR->isCheckShortcut_ = true;
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
    tmp.clear();
    keyOption->SetPreKeys(tmp);
    keyOption->finalKey_ = 4;
    keyEvent->SetKeyCode(4);
    keyEvent->actionTime_ = 3000;
    keyOption->finalKeyDownDuration_ = 3;
    subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    KEY_SHORTCUT_MGR->isCheckShortcut_ = true;
    ret = handler.HandleKeyUp(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_004
 * @tc.desc: Test the function HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_004, TestSize.Level1)
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
}

#ifdef OHOS_BUILD_ENABLE_CALL_MANAGER
/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_01
 * @tc.desc: Test the function HandleRingMute
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
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_08
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr = nullptr;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_09
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr;
    callManagerClientPtr = std::make_shared<OHOS::Telephony::CallManagerClient>();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_10
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr;
    callManagerClientPtr = std::make_shared<OHOS::Telephony::CallManagerClient>();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_UP;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_11
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_11, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_DOWN;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr;
    callManagerClientPtr = std::make_shared<OHOS::Telephony::CallManagerClient>();
    EXPECT_NE(callManagerClientPtr, nullptr);
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    keyEvent->keyCode_ = KeyEvent::KEYCODE_POWER;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}
#endif // OHOS_BUILD_ENABLE_CALL_MANAGER

/**
 * @tc.name: KeySubscriberHandlerTest_AddKeyGestureSubscriber_01
 * @tc.desc: Test AddKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddKeyGestureSubscriber_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscriber->timerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(handler.AddKeyGestureSubscriber(subscriber, keyOption));
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddKeyGestureSubscriber_02
 * @tc.desc: Test AddKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddKeyGestureSubscriber_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(3, sess, keyOption);
    subscriber->timerId_ = 1;

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetFinalKey(1);
    keyOption1->SetFinalKeyDown(true);
    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetFinalKey(1);
    keyOption2->SetFinalKeyDown(true);

    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    auto subscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    auto subscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    handler.keyGestures_.insert({keyOption2, subscribers});

    for (auto &iter : handler.keyGestures_) {
        EXPECT_TRUE(handler.IsEqualKeyOption(keyOption1, iter.first));
    }
    ASSERT_NO_FATAL_FAILURE(handler.AddKeyGestureSubscriber(subscriber, keyOption1));
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddKeyGestureSubscriber_03
 * @tc.desc: Test AddKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddKeyGestureSubscriber_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(3, sess, keyOption);
    subscriber->timerId_ = 2;

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetFinalKey(2);
    keyOption1->SetFinalKeyDown(true);
    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetFinalKey(1);
    keyOption2->SetFinalKeyDown(false);

    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    auto subscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    auto subscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    handler.keyGestures_.insert({keyOption2, subscribers});

    for (auto &iter : handler.keyGestures_) {
        EXPECT_FALSE(handler.IsEqualKeyOption(keyOption1, iter.first));
    }
    ASSERT_NO_FATAL_FAILURE(handler.AddKeyGestureSubscriber(subscriber, keyOption1));
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveKeyGestureSubscriber_01
 * @tc.desc: Test RemoveKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveKeyGestureSubscriber_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_NE(sess, nullptr);

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetFinalKey(2);
    keyOption1->SetFinalKeyDown(true);
    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetFinalKey(1);
    keyOption2->SetFinalKeyDown(false);

    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    auto subscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    handler.keyGestures_.insert({keyOption2, subscribers});

    int32_t subscribeId = 3;
    for (auto &iter : handler.keyGestures_) {
        for (auto innerIter = iter.second.begin(); innerIter != iter.second.end(); ++innerIter) {
        auto subscriber = *innerIter;
        EXPECT_TRUE(subscriber->id_ != subscribeId);
        EXPECT_FALSE(subscriber->sess_ != sess);
    }
    int32_t ret = handler.RemoveKeyGestureSubscriber(sess, subscribeId);
    EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: InputWindowsManagerTest_UnsubscribeKeyEvent_01
 * @tc.desc: Test UnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, InputWindowsManagerTest_UnsubscribeKeyEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_NE(sess, nullptr);
    int32_t subscribeId = 2;
    int32_t ret1 = keySubscriberHandler.RemoveSubscriber(sess, subscribeId, true);
    EXPECT_EQ(ret1, RET_ERR);
    int32_t ret2 = keySubscriberHandler.UnsubscribeKeyEvent(sess, subscribeId);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_01
 * @tc.desc: Test NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_NE(sess, nullptr);
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    EXPECT_NE(subscriber, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_POWER;
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_02
 * @tc.desc: Test NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_NE(sess, nullptr);
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    EXPECT_NE(subscriber, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_UP;
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSubscribeKeyEvent_004
 * @tc.desc: Test the function OnSubscribeKeyEvent
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
 * @tc.desc: Test the function NotifySubscriber
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
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_005
 * @tc.desc: Test NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    ASSERT_NE(subscriber, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_CAMERA;
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE));

    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY);
    EXPECT_FALSE(pkt.ChkRWError());
    ASSERT_NO_FATAL_FAILURE(handler.NotifySubscriber(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_003
 * @tc.desc: Test the function HandleKeyDown
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
 * @tc.desc: Test the function SubscriberNotifyNap
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
    napProcess.instance_->napClientPid_ = REMOVE_OBSERVER;
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
    napProcess.instance_->napClientPid_ = UNOBSERVED;
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
    napProcess.instance_->napClientPid_ = 10;
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscriberNotifyNap_003
 * @tc.desc: Test the function SubscriberNotifyNap
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
    napProcess.instance_->napClientPid_ = ACTIVE_EVENT;
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = 2;
    napData.uid = 3;
    napData.bundleName = "programName";
    EXPECT_FALSE(napProcess.IsNeedNotify(napData));
    ASSERT_NO_FATAL_FAILURE(handler.SubscriberNotifyNap(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscribeKeyEvent_003
 * @tc.desc: Test subscribe keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscribeKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::set<int32_t> preKeys = { 2017, 2018, 2019, 2072, 2046 };
    keyOption->SetPreKeys(preKeys);
    EXPECT_EQ(handler.SubscribeKeyEvent(sess, subscribeId, keyOption), RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscribeKeyEvent_004
 * @tc.desc: Test subscribe keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscribeKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(2072);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(100);
    EXPECT_NE(handler.SubscribeKeyEvent(sess, subscribeId, keyOption), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveKeyGestureSubscriber
 * @tc.desc: Test RemoveKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveKeyGestureSubscriber, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> listSub;
    listSub.push_back(subscriber);
    subscribeId = 2;
    handler.keyGestures_.insert(std::make_pair(keyOption, listSub));
    EXPECT_EQ(handler.RemoveKeyGestureSubscriber(sess, subscribeId), RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveKeyGestureSubscriber_001
 * @tc.desc: Test RemoveKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveKeyGestureSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> listSub;
    listSub.push_back(subscriber);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    handler.keyGestures_.insert(std::make_pair(keyOption, listSub));
    EXPECT_EQ(handler.RemoveKeyGestureSubscriber(session, subscribeId), RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveKeyGestureSubscriber_002
 * @tc.desc: Test RemoveKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveKeyGestureSubscriber_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> listSub;
    listSub.push_back(subscriber);
    handler.keyGestures_.insert(std::make_pair(keyOption, listSub));
    EXPECT_EQ(handler.RemoveKeyGestureSubscriber(sess, subscribeId), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSessionDelete_002
 * @tc.desc: Test OnSessionDelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSessionDelete_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();

    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> listSub;
    listSub.push_back(subscriber);

    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeySubscriberHandler::Subscriber> keySubscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, session, keyOption);
    listSub.push_back(keySubscriber);
    handler.keyGestures_.insert(std::make_pair(keyOption, listSub));
    EXPECT_NO_FATAL_FAILURE(handler.OnSessionDelete(session));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnSessionDelete_003
 * @tc.desc: Test OnSessionDelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnSessionDelete_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> listSub;
    handler.keyGestures_.insert(std::make_pair(keyOption, listSub));
    EXPECT_NO_FATAL_FAILURE(handler.OnSessionDelete(sess));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDelay_03
 * @tc.desc: Test HandleKeyUpWithDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDelay_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyUpDelay(-1);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    EXPECT_NO_FATAL_FAILURE(handler.HandleKeyUpWithDelay(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDelay_04
 * @tc.desc: Test HandleKeyUpWithDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDelay_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyUpDelay(100);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    EXPECT_NO_FATAL_FAILURE(handler.HandleKeyUpWithDelay(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_DumpSubscriber
 * @tc.desc: Test DumpSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_DumpSubscriber, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyUpDelay(100);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    int32_t fd = 100;
    EXPECT_NO_FATAL_FAILURE(handler.DumpSubscriber(fd, subscriber));

    std::shared_ptr<KeyOption> option = std::make_shared<KeyOption>();
    std::set<int32_t> preKeys = { 2020, 2021 };
    option->SetPreKeys(preKeys);
    subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, option);
    EXPECT_NO_FATAL_FAILURE(handler.DumpSubscriber(fd, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_InitDataShareListener
 * @tc.desc: Test InitDataShareListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_InitDataShareListener, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    EXPECT_NO_FATAL_FAILURE(handler.InitDataShareListener());
}

#ifdef OHOS_BUILD_ENABLE_CALL_MANAGER
/**
 * @tc.name: KeySubscriberHandlerTest_RejectCallProcess
 * @tc.desc: Test RejectCallProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RejectCallProcess, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    EXPECT_NO_FATAL_FAILURE(handler.RejectCallProcess());
}

/**
 * @tc.name: KeySubscriberHandlerTest_HangUpCallProcess
 * @tc.desc: Test HangUpCallProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HangUpCallProcess, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    EXPECT_NO_FATAL_FAILURE(handler.HangUpCallProcess());
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = false;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = true;
    handler.callEndKeyUp_ = false;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = true;
    handler.callEndKeyUp_ = true;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ret = handler.HandleCallEnded(keyEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = true;
    handler.callEndKeyUp_ = true;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = true;
    handler.callEndKeyUp_ = false;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = true;
    handler.callEndKeyUp_ = false;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    DEVICE_MONITOR->callState_ = CALL_STATUS_DISCONNECTED;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}


/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = false;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
    handler.callBahaviorState_ = true;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_DIALING;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DEVICE_MONITOR->callState_ = CALL_STATUS_INCOMING;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DEVICE_MONITOR->callState_ = 10;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberTimer_001
 * @tc.desc: Test RemoveSubscriberTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    for (auto i = 0; i < 5; i++) {
        KeyEvent::KeyItem keyItem;
        keyItem.SetKeyCode(KeyEvent::KEYCODE_POWER);
        keyItem.SetPressed(true);
        keyEvent->keys_.push_back(keyItem);
    }
    EXPECT_NO_FATAL_FAILURE(handler.RemoveSubscriberTimer(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberTimer_002
 * @tc.desc: Test RemoveSubscriberTimer when VOLUME_DOWN event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberTimer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    handler.needSkipPowerKeyUp_ = true;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    for (auto i = 0; i < 5; i++) {
        KeyEvent::KeyItem keyItem;
        keyItem.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
        keyItem.SetPressed(true);
        keyEvent->keys_.push_back(keyItem);
    }
    handler.RemoveSubscriberTimer(keyEvent);
    EXPECT_FALSE(handler.needSkipPowerKeyUp_);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberTimer_003
 * @tc.desc: Test RemoveSubscriberTimer when VOLUME_UP event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberTimer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    handler.needSkipPowerKeyUp_ = true;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    for (auto i = 0; i < 5; i++) {
        KeyEvent::KeyItem keyItem;
        keyItem.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
        keyItem.SetPressed(true);
        keyEvent->keys_.push_back(keyItem);
    }
    handler.RemoveSubscriberTimer(keyEvent);
    EXPECT_FALSE(handler.needSkipPowerKeyUp_);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberTimer_004
 * @tc.desc: Test RemoveSubscriberTimer not reset the flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberTimer_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    handler.needSkipPowerKeyUp_ = true;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    for (auto i = 0; i < 5; i++) {
        KeyEvent::KeyItem keyItem;
        keyItem.SetKeyCode(KeyEvent::KEYCODE_POWER);
        keyItem.SetPressed(true);
        keyEvent->keys_.push_back(keyItem);
    }
    handler.RemoveSubscriberTimer(keyEvent);
    EXPECT_TRUE(handler.needSkipPowerKeyUp_);
}
#endif // OHOS_BUILD_ENABLE_CALL_MANAGER

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberKeyUpTimer
 * @tc.desc: Test RemoveSubscriberKeyUpTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberKeyUpTimer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    EXPECT_NO_FATAL_FAILURE(handler.RemoveSubscriberKeyUpTimer(KeyEvent::KEYCODE_POWER));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyEvent_002
 * @tc.desc: Test HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:nhj
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyEvent_002, TestSize.Level1)
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
    EXPECT_FALSE(handler.OnSubscribeKeyEvent(keyEvent));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));

    handler.enableCombineKey_ = true;
    handler.hasEventExecuting_ = true;
    handler.keyEvent_ = KeyEvent::Create();
    ASSERT_NE(handler.keyEvent_, nullptr);
    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
    handler.keyEvent_->SetKeyCode(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    handler.keyEvent_->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetFourceMonitorFlag(true);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    handler.keyEvent_->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    handler.keyEvent_->AddKeyItem(item);
    EXPECT_TRUE(handler.OnSubscribeKeyEvent(keyEvent));
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddKeyGestureSubscriber_04
 * @tc.desc: Test AddKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddKeyGestureSubscriber_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(3, sess, keyOption);
    subscriber->timerId_ = 1;

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetFinalKey(1);
    keyOption1->SetFinalKeyDown(false);
    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetFinalKey(1);
    keyOption2->SetFinalKeyDown(true);

    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    auto subscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    auto subscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    handler.keyGestures_.insert({keyOption2, subscribers});

    for (auto &iter : handler.keyGestures_) {
        EXPECT_FALSE(handler.IsEqualKeyOption(keyOption1, iter.first));
    }
    EXPECT_EQ(handler.AddKeyGestureSubscriber(subscriber, keyOption), RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddKeyGestureSubscriber_05
 * @tc.desc: Test AddKeyGestureSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddKeyGestureSubscriber_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    subscriber->timerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(handler.AddKeyGestureSubscriber(subscriber, keyOption));
    EXPECT_EQ(handler.AddKeyGestureSubscriber(subscriber, keyOption), RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_SubscribeHotkey
 * @tc.desc: Test SubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_SubscribeHotkey, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::set<int32_t> preKeys;
    preKeys.insert(1);
    keyOption->SetPreKeys(preKeys);
    uint32_t preKeySize = keyOption->GetPreKeys().size();
    ASSERT_NE(preKeySize, MAX_PRE_KEY_COUNT);
    ASSERT_NE(handler.SubscribeHotkey(sess, subscribeId, keyOption), RET_OK);
    preKeys.insert(2);
    preKeys.insert(3);
    preKeys.insert(4);
    preKeys.insert(5);
    preKeys.insert(6);
    keyOption->SetPreKeys(preKeys);
    ASSERT_EQ(handler.SubscribeHotkey(sess, subscribeId, keyOption), RET_ERR);
}

/**
 * @tc.name: KeySubscriberHandlerTest_UnsubscribeHotkey
 * @tc.desc: Test UnsubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_UnsubscribeHotkey, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    int32_t id = 1;
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    subscriberList.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscriberList));
    ASSERT_NE(handler.UnsubscribeHotkey(session, subscribeId), RET_ERR);
}

#ifdef OHOS_BUILD_ENABLE_CALL_MANAGER
/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = false;
    handler.callBahaviorState_ = false;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
    handler.callBahaviorState_ = true;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CUSTOM1);
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_DIALING;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DEVICE_MONITOR->callState_ = CALL_STATUS_INCOMING;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DEVICE_MONITOR->callState_ = 10;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleCallEnded
 * @tc.desc: Test HandleCallEnded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleCallEnded002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    bool ret = true;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CUSTOM1);

    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_DIALING;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DEVICE_MONITOR->callState_ = CALL_STATUS_WAITING;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DEVICE_MONITOR->callState_ = CALL_STATUS_DISCONNECTED;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);

    DEVICE_MONITOR->callState_ = CALL_STATUS_DISCONNECTING;
    ret = handler.HandleCallEnded(keyEvent);
    ASSERT_FALSE(ret);
}
#endif // OHOS_BUILD_ENABLE_CALL_MANAGER

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberKeyUpTimer
 * @tc.desc: Test RemoveSubscriberKeyUpTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberKeyUpTimer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);

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
    EXPECT_NO_FATAL_FAILURE(handler.RemoveSubscriberKeyUpTimer(KeyEvent::KEYCODE_POWER));
    for (auto& sub : subscriberMap_) {
        ASSERT_EQ(sub->timerId_, -1);
        ASSERT_NE(sub->keyOption_->GetFinalKey(), KeyEvent::KEYCODE_POWER);
    }
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_007
 * @tc.desc: Test Is Enable CombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_007, TestSize.Level1)
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

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_R);
    ASSERT_FALSE(handler.IsEnableCombineKey(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKeyRecord_001
 * @tc.desc: Test is enable combine key record
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKeyRecord_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    ASSERT_TRUE(handler.IsEnableCombineKeyRecord(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    ASSERT_TRUE(handler.IsEnableCombineKeyRecord(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    ASSERT_TRUE(handler.IsEnableCombineKeyRecord(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    ASSERT_TRUE(handler.IsEnableCombineKeyRecord(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    ASSERT_TRUE(handler.IsEnableCombineKeyRecord(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_InterceptByVm_001
 * @tc.desc: Test InterceptByVm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_InterceptByVm_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    ASSERT_TRUE(handler.InterceptByVm(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    ASSERT_TRUE(handler.InterceptByVm(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_E);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_E);
    ASSERT_FALSE(handler.InterceptByVm(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_InterceptByVm_002
 * @tc.desc: Test InterceptByVm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_InterceptByVm_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    const std::vector<int32_t> LOGO_LEFTSHIFT_E = {
        KeyEvent::KEYCODE_META_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT, KeyEvent::KEYCODE_E};
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    item.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    item.SetKeyCode(KeyEvent::KEYCODE_E);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_E);
    ASSERT_FALSE(handler.InterceptByVm(keyEvent));
    for (auto&& keyItem : keyEvent->GetKeyItems()) {
        for (auto &&k : LOGO_LEFTSHIFT_E) {
            if (keyItem.GetKeyCode() == k) {
                ASSERT_FALSE(handler.InterceptByVm(keyEvent));
            }
        }
    }
    size_t waitMatchCnt{LOGO_LEFTSHIFT_E.size()};
    ASSERT_NE(waitMatchCnt, 0);
    ASSERT_NO_FATAL_FAILURE(handler.InterceptByVm(keyEvent));
}

#ifdef OHOS_BUILD_ENABLE_CALL_MANAGER
/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_011
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_VOLUME_UP;

    DEVICE_MONITOR->callState_ = StateType::CALL_STATUS_INCOMING;
    std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr = nullptr;
    ASSERT_FALSE(keySubscriberHandler.HandleRingMute(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleRingMute_012
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleRingMute_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 1;
    DEVICE_MONITOR->SetCallState(data, callState);
    bool result = keySubscriberHandler.HandleRingMute(keyEvent);
    ASSERT_FALSE(result);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
    ASSERT_FALSE(keySubscriberHandler.needSkipPowerKeyUp_);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    result = keySubscriberHandler.HandleRingMute(keyEvent);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleVoipRingMute_002
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleVoipRingMute_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler keySubscriberHandler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    OHOS::EventFwk::Want want;
    want.SetParam("state", StateType::CALL_STATUS_INCOMING);
    OHOS::EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 1;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    bool result = keySubscriberHandler.HandleRingMute(keyEvent);
    ASSERT_FALSE(result);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
    ASSERT_FALSE(keySubscriberHandler.needSkipPowerKeyUp_);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    result = keySubscriberHandler.HandleRingMute(keyEvent);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}
#endif // OHOS_BUILD_ENABLE_CALL_MANAGER


/**
 * @tc.name: KeySubscriberHandlerTest_ProcessKeyEvent_01
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessKeyEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CAMERA);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE));
    ASSERT_NO_FATAL_FAILURE(handler.ProcessKeyEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessKeyEvent_02
 * @tc.desc: Test ring mute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessKeyEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    SessionPtr sess;
    std::shared_ptr<KeyOption> keyOption;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    handler.needSkipPowerKeyUp_ = true;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    std::vector<int32_t> pressedKeys;
    pressedKeys.push_back(KeyEvent::KEYCODE_B);
    pressedKeys.push_back(KeyEvent::KEYCODE_C);
    KeyEvent::KeyItem item;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->AddKeyItem(item);
    keyEvent->AddPressedKeyItems(item);

    bool result = handler.ProcessKeyEvent(keyEvent);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifySubscriber_006
 * @tc.desc: Test the function NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifySubscriber_006, TestSize.Level1)
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
 * @tc.name: KeySubscriberHandlerTest_AddTimer_002
 * @tc.desc: Test the function AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddTimer_002, TestSize.Level1)
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
    subscriber->keyOption_->SetFinalKeyDown(true);
    subscriber->keyOption_->SetFinalKeyDownDuration(0);
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
    subscriber->keyOption_->SetFinalKeyDown(false);
    ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddTimer_003
 * @tc.desc: Test the function AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddTimer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t id = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    bool ret = handler.AddTimer(subscriber, nullptr);
    ASSERT_FALSE(ret);
    ret = handler.AddTimer(nullptr, keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddTimer_004
 * @tc.desc: Test the function AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddTimer_004, TestSize.Level1)
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
    ASSERT_TRUE(handler.CloneKeyEvent(keyEvent));
    auto ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddTimer_005
 * @tc.desc: Test the function AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddTimer_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t id = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(id, session, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    subscriber->timerId_ = -1;
    bool ret = handler.AddTimer(subscriber, keyEvent);
    ASSERT_FALSE(ret);
    ASSERT_FALSE(handler.CloneKeyEvent(keyEvent));
}
#ifdef OHOS_BUILD_ENABLE_PEN
/**
 * @tc.name: TabletSubscriberHandlerTest_SubscribeTabletProximity
 * @tc.desc: Test the function AboutSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, TabletSubscriberHandlerTest_SubscribeTabletProximity, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto tabletSubscriberHandler = TABLET_SCRIBER_HANDLER;
    SessionPtr sess;
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->SubscribeTabletProximity(sess, 0));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->SubscribeTabletProximity(sess, -1));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->SubscribeTabletProximity(sess, 1));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->SubscribeTabletProximity(sess, 0));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->SubscribeTabletProximity(nullptr, 0));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->UnsubscribetabletProximity(nullptr, 0));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->UnsubscribetabletProximity(nullptr, -1));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->UnsubscribetabletProximity(sess, 0));
}

/**
 * @tc.name: TabletSubscriberHandlerTest_OnSubscribeTabletProximity
 * @tc.desc: Test the function OnSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, TabletSubscriberHandlerTest_OnSubscribeTabletProximity, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto tabletSubscriberHandler = TABLET_SCRIBER_HANDLER;
    SessionPtr sess;
    tabletSubscriberHandler->SubscribeTabletProximity(sess, 0);
    auto pointerEvent = std::make_shared<PointerEvent>(0);
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->OnSubscribeTabletProximity(pointerEvent));
    auto pointerEvent2 = std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_OUT);
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->OnSubscribeTabletProximity(pointerEvent2));
    auto pointerEvent3 = std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->OnSubscribeTabletProximity(pointerEvent3));
}

/**
 * @tc.name: TabletSubscriberHandlerTest_OnSessionDelete
 * @tc.desc: Test the function OnSessionDelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, TabletSubscriberHandlerTest_OnSessionDelete, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto tabletSubscriberHandler = TABLET_SCRIBER_HANDLER;
    SessionPtr sess;
    SessionPtr sess2;
    tabletSubscriberHandler->SubscribeTabletProximity(sess, 0);
    tabletSubscriberHandler->SubscribeTabletProximity(sess2, 0);
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->OnSessionDelete(sess));
    ASSERT_NO_FATAL_FAILURE(tabletSubscriberHandler->OnSessionDelete(sess));
}
#endif // OHOS_BUILD_ENABLE_PEN
/**
 * @tc.name: KeySubscriberHandlerTest_IsPreKeysMatch_002
 * @tc.desc: Test is preKeys match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsPreKeysMatch_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::set<int32_t> preKeys = {};
    std::vector<int32_t> pressedKeys = {1, 2, 3};
    bool result = handler.IsPreKeysMatch(preKeys, pressedKeys);
    EXPECT_TRUE(result);
    preKeys = {1, 2};
    result = handler.IsPreKeysMatch(preKeys, pressedKeys);
    EXPECT_FALSE(result);
    preKeys = {1, 2, 3};
    pressedKeys = {1, 2, 4};
    result = handler.IsPreKeysMatch(preKeys, pressedKeys);
    EXPECT_FALSE(result);
    pressedKeys = {1, 2, 3};
    preKeys = {1, 2, 3};
    result = handler.IsPreKeysMatch(preKeys, pressedKeys);
    EXPECT_TRUE(result);
    pressedKeys = {};
    preKeys = {};
    result = handler.IsPreKeysMatch(preKeys, pressedKeys);
    EXPECT_TRUE(result);
    pressedKeys = {3, 1, 2};
    preKeys = {2, 3, 1};
    result = handler.IsPreKeysMatch(preKeys, pressedKeys);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEqualPreKeys_002
 * @tc.desc: Test is equal preKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEqualPreKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::set<int32_t> preKeys = {};
    std::set<int32_t> pressedKeys = {};
    bool result = handler.IsEqualPreKeys(preKeys, pressedKeys);
    EXPECT_TRUE(result);
    pressedKeys = {3, 1, 2};
    preKeys = {2, 3, 1};
    result = handler.IsEqualPreKeys(preKeys, pressedKeys);
    EXPECT_TRUE(result);
    preKeys = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    pressedKeys = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    result = handler.IsEqualPreKeys(preKeys, pressedKeys);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsMatchForegroundPid_002
 * @tc.desc: Test Is Match Foreground Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsMatchForegroundPid_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscriberList = {};
    std::set<int32_t> foregroundPids = {};
    bool result = handler.IsMatchForegroundPid(subscriberList, foregroundPids);
    EXPECT_FALSE(result);
    EXPECT_FALSE(handler.isForegroundExits_);
    EXPECT_TRUE(handler.foregroundPids_.empty());
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsMatchForegroundPid_003
 * @tc.desc: Test Is Match Foreground Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsMatchForegroundPid_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);
    auto session2 = std::make_shared<UDSSession>("test2", 2, 2, 200, 1002);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, nullptr);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1, subscriber2};
    std::set<int32_t> foregroundPids = {2001, 2002};
    
    bool result = handler.IsMatchForegroundPid(subs, foregroundPids);
    EXPECT_FALSE(result);
    EXPECT_FALSE(handler.isForegroundExits_);
    EXPECT_TRUE(handler.foregroundPids_.empty());
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsMatchForegroundPid_004
 * @tc.desc: Test Is Match Foreground Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsMatchForegroundPid_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);
    auto session2 = std::make_shared<UDSSession>("test2", 2, 2, 200, 1002);
    auto session3 = std::make_shared<UDSSession>("test2", 3, 3, 300, 1003);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, nullptr);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, nullptr);
    auto subscriber3 = std::make_shared<KeySubscriberHandler::Subscriber>(3, session3, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1, subscriber2, subscriber3};
    std::set<int32_t> foregroundPids = {1001, 1003, 2001};
    
    bool result = handler.IsMatchForegroundPid(subs, foregroundPids);
    EXPECT_TRUE(result);
    EXPECT_TRUE(handler.isForegroundExits_);
    EXPECT_EQ(handler.foregroundPids_.size(), 2UL);
    EXPECT_TRUE(handler.foregroundPids_.find(1001) != handler.foregroundPids_.end());
    EXPECT_TRUE(handler.foregroundPids_.find(1003) != handler.foregroundPids_.end());

    foregroundPids = {1001, 1002, 1003};
    result = handler.IsMatchForegroundPid(subs, foregroundPids);
    EXPECT_TRUE(result);
    EXPECT_TRUE(handler.isForegroundExits_);
    EXPECT_EQ(handler.foregroundPids_.size(), 3UL);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsMatchForegroundPid_005
 * @tc.desc: Test Is Match Foreground Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsMatchForegroundPid_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1};
    std::set<int32_t> foregroundPids = {};
    
    bool result = handler.IsMatchForegroundPid(subs, foregroundPids);
    EXPECT_FALSE(result);
    EXPECT_FALSE(handler.isForegroundExits_);
    EXPECT_TRUE(handler.foregroundPids_.empty());
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownSubscriber_002
 * @tc.desc: Test Notify Key Down Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownSubscriber_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    bool handled = false;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDownDuration(0);
    keyOption->SetRepeat(true);
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1};
    
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownSubscriber(keyEvent, keyOption, subs, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_GetHighestPrioritySubscriber
 * @tc.desc: Test Notify Key Down Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_GetHighestPrioritySubscriber, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPriority(10);
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption);

    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1};
    auto result = handler.GetHighestPrioritySubscriber(subs);
    EXPECT_EQ(result, 10);
}

/**
 * @tc.name: KeySubscriberHandlerTest_GetHighestPrioritySubscriber_001
 * @tc.desc: Test Notify Key Down Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_GetHighestPrioritySubscriber_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);

    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(5);
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(10);
    std::shared_ptr<KeyOption> keyOption3 = std::make_shared<KeyOption>();
    keyOption3->SetPriority(15);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session1, keyOption2);
    auto subscriber3 = std::make_shared<KeySubscriberHandler::Subscriber>(3, session1, keyOption3);

    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1, subscriber2, subscriber3};
    auto result = handler.GetHighestPrioritySubscriber(subs);
    EXPECT_EQ(result, 15);
}

/**
 * @tc.name: KeySubscriberHandlerTest_GetHighestPrioritySubscriber_002
 * @tc.desc: Test Notify Key Down Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_GetHighestPrioritySubscriber_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);

    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(20);
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(20);
    std::shared_ptr<KeyOption> keyOption3 = std::make_shared<KeyOption>();
    keyOption3->SetPriority(20);
    
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session1, keyOption2);
    auto subscriber3 = std::make_shared<KeySubscriberHandler::Subscriber>(3, session1, keyOption3);

    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1, subscriber2, subscriber3};
    auto result = handler.GetHighestPrioritySubscriber(subs);
    EXPECT_EQ(result, 20);
}

/**
 * @tc.name: KeySubscriberHandlerTest_GetHighestPrioritySubscriber_003
 * @tc.desc: Test Notify Key Down Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_GetHighestPrioritySubscriber_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);

    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(-5);
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(-20);
    std::shared_ptr<KeyOption> keyOption3 = std::make_shared<KeyOption>();
    keyOption3->SetPriority(-1);
    
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session1, keyOption2);
    auto subscriber3 = std::make_shared<KeySubscriberHandler::Subscriber>(3, session1, keyOption3);

    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1, subscriber2, subscriber3};
    auto result = handler.GetHighestPrioritySubscriber(subs);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_GetHighestPrioritySubscriber_004
 * @tc.desc: Test Notify Key Down Subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_GetHighestPrioritySubscriber_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);

    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPriority(10);

    auto validSubscriber = std::make_shared<KeySubscriberHandler::Subscriber>(1, session, keyOption);
    auto invalidSubscriber = std::make_shared<KeySubscriberHandler::Subscriber>(2, session, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers = {
        invalidSubscriber,
        validSubscriber
    };
    
    int32_t result = handler.GetHighestPrioritySubscriber(subscribers);
    EXPECT_EQ(result, 10);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownRightNow_002
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownRightNow_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool handled = false;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);
    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(15);
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);

    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1};
    
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownRightNow(keyEvent, subs, false, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownRightNow_003
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownRightNow_003, TestSize.Level1)
{
    KeySubscriberHandler handler;
    handler.isForegroundExits_ = true;
    handler.foregroundPids_ = {1001};
    bool handled = false;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);

    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(15);
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(15);
    std::shared_ptr<KeyOption> keyOption3 = std::make_shared<KeyOption>();
    keyOption3->SetPriority(10);
    
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session1, keyOption2);
    auto subscriber3 = std::make_shared<KeySubscriberHandler::Subscriber>(3, session1, keyOption3);

    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1, subscriber2, subscriber3};
    handler.NotifyKeyDownRightNow(keyEvent, subs, false, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownRightNow_004
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownRightNow_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    handler.isForegroundExits_ = true;
    handler.foregroundPids_ = {1001};
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool handled = false;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);
    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(10);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    
    handler.NotifyKeyDownRightNow(keyEvent, subscribers, false, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_002
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    handler.isForegroundExits_ = false;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool handled = false;
    auto session1 = std::make_shared<UDSSession>("test1", 1, 1, 100, 1001);
    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(10);
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);

    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subs = {subscriber1};

    handler.NotifyKeyDownDelay(keyEvent, subs, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_003
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool handled = false;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 200);
    std::shared_ptr<KeyOption> keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(1);
    std::shared_ptr<KeyOption> keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(2);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, keyOption2);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);

    handler.isForegroundExits_ = true;
    handler.foregroundPids_ = {100, 300};
    
    handler.NotifyKeyDownDelay(keyEvent, subscribers, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_004
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_B);

    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 200);
    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(1);
    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(2);
    
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, keyOption2);
    
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    handler.isForegroundExits_ = true;
    handler.foregroundPids_ = {300, 400};
    
    bool handled = false;
    handler.NotifyKeyDownDelay(keyEvent, subscribers, handled);
    handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_005
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 200);
    
    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(1);
    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(1);
    
    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, keyOption2);
    
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    
    handler.isForegroundExits_ = false;
    handler.foregroundPids_ = {};
    
    bool handled = false;
    handler.NotifyKeyDownDelay(keyEvent, subscribers, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_006
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    handler.isForegroundExits_ = true;
    handler.foregroundPids_ = {100};
    
    bool handled = false;
    handler.NotifyKeyDownDelay(keyEvent, subscribers, handled);
    handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_007
 * @tc.desc: Test Notify Key Down Right Now
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_D);

    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 200);
    SessionPtr session3 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 300);
    
    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetPriority(1);
    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetPriority(3);
    auto keyOption3 = std::make_shared<KeyOption>();
    keyOption3->SetPriority(3);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, keyOption2);
    auto subscriber3 = std::make_shared<KeySubscriberHandler::Subscriber>(3, session3, keyOption3);
    
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    subscribers.push_back(subscriber3);
    
    handler.isForegroundExits_ = true;
    handler.foregroundPids_ = {100, 200, 300};
    bool handled = false;
    handler.NotifyKeyDownDelay(keyEvent, subscribers, handled);
    handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_004
 * @tc.desc: Test the funcation HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDown(false);

    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(1, session, keyOption);
    handler.subscriberMap_[keyOption] = {subscriber};

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool result = handler.HandleKeyDown(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_005
 * @tc.desc: Test the funcation HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;

    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetFinalKeyDownDuration(0);

    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(1, session, keyOption);
    handler.subscriberMap_[keyOption] = {subscriber};

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool result = handler.HandleKeyDown(keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_006
 * @tc.desc: Test the funcation HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 101);
    
    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetFinalKeyDown(true);
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption1->SetFinalKeyDownDuration(0);
    keyOption1->SetPriority(1);

    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetFinalKeyDown(true);
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption2->SetFinalKeyDownDuration(0);
    keyOption2->SetPriority(10);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, keyOption2);
    handler.subscriberMap_[keyOption1] = {subscriber1};
    handler.subscriberMap_[keyOption2] = {subscriber2};

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool result = handler.HandleKeyDown(keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_007
 * @tc.desc: Test HandleKeyDown with non-matching key code
 * @tc.type: FUNC
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;

    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_B);

    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(1, session, keyOption);
    handler.subscriberMap_[keyOption] = {subscriber};

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool result = handler.HandleKeyDown(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_008
 * @tc.desc: Test HandleKeyDown with non-matching key code
 * @tc.type: FUNC
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_008, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;

    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);

    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(1, session, keyOption);
    handler.subscriberMap_[keyOption] = {subscriber};

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);

    bool result = handler.HandleKeyDown(keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_005
 * @tc.desc: Test the funcation HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;

    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 100);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, 101);

    auto keyOption1 = std::make_shared<KeyOption>();
    keyOption1->SetFinalKeyDown(false);
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption1->SetFinalKeyDownDuration(0);
    keyOption1->SetPriority(1);

    auto keyOption2 = std::make_shared<KeyOption>();
    keyOption2->SetFinalKeyDown(false);
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption2->SetFinalKeyDownDuration(0);
    keyOption2->SetPriority(10);

    auto subscriber1 = std::make_shared<KeySubscriberHandler::Subscriber>(1, session1, keyOption1);
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, session2, keyOption2);
    handler.subscriberMap_[keyOption1] = {subscriber1};
    handler.subscriberMap_[keyOption2] = {subscriber2};
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool result = handler.HandleKeyUp(keyEvent);
    EXPECT_FALSE(result);
}

#ifdef SHORTCUT_KEY_MANAGER_ENABLED
/**
 * @tc.name: KeySubscriberHandlerTest_RegisterSystemKey_001
 * @tc.desc: Test RegisterSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RegisterSystemKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_META_LEFT);
    std::set<int32_t> modifiers = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(modifiers);
    std::function<void(std::shared_ptr<KeyEvent>)> callback = [](std::shared_ptr<KeyEvent> keyEvent) {};
    ASSERT_NE(handler.RegisterSystemKey(keyOption, 100, callback), -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RegisterSystemKey_002
 * @tc.desc: Test RegisterSystemKey with pure modifiers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RegisterSystemKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_META_LEFT);
    keyOption->SetFinalKeyDown(true);
    std::set<int32_t> modifiers = {KeyEvent::KEYCODE_CTRL_LEFT, KeyEvent::KEYCODE_SHIFT_LEFT};
    keyOption->SetPreKeys(modifiers);
    std::function<void(std::shared_ptr<KeyEvent>)> callback = [](std::shared_ptr<KeyEvent> keyEvent) {};
    ASSERT_NE(handler.RegisterSystemKey(keyOption, 100, callback), -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RegisterHotKey_001
 * @tc.desc: Test RegisterHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RegisterHotKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> modifiers = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(modifiers);
    std::function<void(std::shared_ptr<KeyEvent>)> callback = [](std::shared_ptr<KeyEvent> keyEvent) {};
    ASSERT_NE(handler.RegisterHotKey(keyOption, 100, callback), -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_RegisterHotKey_002
 * @tc.desc: Test RegisterHotKey with long press time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RegisterHotKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_B);
    keyOption->SetFinalKeyDownDuration(500);
    std::function<void(std::shared_ptr<KeyEvent>)> callback = [](std::shared_ptr<KeyEvent> keyEvent) {};
    ASSERT_NE(handler.RegisterHotKey(keyOption, 200, callback), -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_UnregisterSystemKey_001
 * @tc.desc: Test UnregisterSystemKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_UnregisterSystemKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t shortcutId = 1;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterSystemKey(shortcutId));
    shortcutId = -1;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterSystemKey(shortcutId));
}

/**
 * @tc.name: KeySubscriberHandlerTest_UnregisterHotKey_001
 * @tc.desc: Test UnregisterHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_UnregisterHotKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t shortcutId = 1;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterHotKey(shortcutId));
    shortcutId = 0;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterHotKey(shortcutId));
}

/**
 * @tc.name: KeySubscriberHandlerTest_DeleteShortcutId_001
 * @tc.desc: Test DeleteShortcutId for system shortcut
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_DeleteShortcutId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto keyOption = std::make_shared<KeyOption>();
    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    subscriber->isSystem = true;
    subscriber->shortcutId_ = 1;
    ASSERT_NO_FATAL_FAILURE(handler.DeleteShortcutId(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_DeleteShortcutId_002
 * @tc.desc: Test DeleteShortcutId for hotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_DeleteShortcutId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto keyOption = std::make_shared<KeyOption>();
    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    subscriber->isSystem = false;
    subscriber->shortcutId_ = 2;
    ASSERT_NO_FATAL_FAILURE(handler.DeleteShortcutId(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_DeleteShortcutId_003
 * @tc.desc: Test DeleteShortcutId with null subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_DeleteShortcutId_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.DeleteShortcutId(nullptr));
}
#endif // SHORTCUT_KEY_MANAGER_ENABLED

/**
 * @tc.name: KeySubscriberHandlerTest_GetForegroundPids_001
 * @tc.desc: Test GetForegroundPids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_GetForegroundPids_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::set<int32_t> pids;
    ASSERT_NO_FATAL_FAILURE(handler.GetForegroundPids(pids));
}

/**
 * @tc.name: KeySubscriberHandlerTest_GetForegroundPids_002
 * @tc.desc: Test GetForegroundPids with multiple pids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_GetForegroundPids_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::set<int32_t> pids;
    pids.insert(100);
    pids.insert(200);
    pids.insert(300);
    ASSERT_NO_FATAL_FAILURE(handler.GetForegroundPids(pids));
    EXPECT_FALSE(pids.empty());
}

/**
 * @tc.name: KeySubscriberHandlerTest_ResetSkipPowerKeyUpFlag_001
 * @tc.desc: Test ResetSkipPowerKeyUpFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ResetSkipPowerKeyUpFlag_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    handler.needSkipPowerKeyUp_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.ResetSkipPowerKeyUpFlag());
    EXPECT_FALSE(handler.needSkipPowerKeyUp_);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ResetSkipPowerKeyUpFlag_002
 * @tc.desc: Test ResetSkipPowerKeyUpFlag when already false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ResetSkipPowerKeyUpFlag_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    handler.needSkipPowerKeyUp_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.ResetSkipPowerKeyUpFlag());
    EXPECT_FALSE(handler.needSkipPowerKeyUp_);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKeySwipe_002
 * @tc.desc: Test IsEnableCombineKeySwipe with invalid keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKeySwipe_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    ASSERT_TRUE(handler.IsEnableCombineKeySwipe(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKeySwipe_003
 * @tc.desc: Test IsEnableCombineKeySwipe with mixed valid/invalid keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKeySwipe_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    ASSERT_TRUE(handler.IsEnableCombineKeySwipe(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKeyRecord_002
 * @tc.desc: Test IsEnableCombineKeyRecord with invalid keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKeyRecord_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    ASSERT_TRUE(handler.IsEnableCombineKeyRecord(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKeyRecord_003
 * @tc.desc: Test IsEnableCombineKeyRecord with mixed valid/invalid keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKeyRecord_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_R);
    ASSERT_TRUE(handler.IsEnableCombineKeyRecord(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_InterceptByVm_003
 * @tc.desc: Test InterceptByVm with different key sizes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_InterceptByVm_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    ASSERT_TRUE(handler.InterceptByVm(keyEvent));

    item.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    ASSERT_TRUE(handler.InterceptByVm(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_InterceptByVm_004
 * @tc.desc: Test InterceptByVm with non-matching keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_InterceptByVm_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    item.SetKeyCode(KeyEvent::KEYCODE_E);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_E);
    ASSERT_TRUE(handler.InterceptByVm(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_PublishKeyPressCommonEvent_001
 * @tc.desc: Test PublishKeyPressCommonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_PublishKeyPressCommonEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.PublishKeyPressCommonEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_PublishKeyPressCommonEvent_002
 * @tc.desc: Test PublishKeyPressCommonEvent with different keycodes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_PublishKeyPressCommonEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_NO_FATAL_FAILURE(handler.PublishKeyPressCommonEvent(keyEvent));

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_MUTE);
    ASSERT_NO_FATAL_FAILURE(handler.PublishKeyPressCommonEvent(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_OnTimer_001
 * @tc.desc: Test OnTimer with null subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_OnTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.OnTimer(nullptr));
}

/**
 * @tc.name: KeySubscriberHandlerTest_ClearTimer_001
 * @tc.desc: Test ClearTimer with null subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ClearTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ClearTimer(nullptr));
}

/**
 * @tc.name: KeySubscriberHandlerTest_ClearSubscriberTimer_003
 * @tc.desc: Test ClearSubscriberTimer with empty subscriber list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ClearSubscriberTimer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    ASSERT_NO_FATAL_FAILURE(handler.ClearSubscriberTimer(subscribers));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyCancel_002
 * @tc.desc: Test HandleKeyCancel with null keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyCancel_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    bool result = handler.HandleKeyCancel(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_Dump_001
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t fd = 100;
    std::vector<std::string> args = {};
    ASSERT_NO_FATAL_FAILURE(handler.Dump(fd, args));
}

/**
 * @tc.name: KeySubscriberHandlerTest_Dump_002
 * @tc.desc: Test Dump with subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_Dump_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t fd = 100;
    std::vector<std::string> args = {"--test"};
    
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto keyOption = std::make_shared<KeyOption>();
    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    ASSERT_NO_FATAL_FAILURE(handler.Dump(fd, args));
}

/**
 * @tc.name: KeySubscriberHandlerTest_CountSubscribers_001
 * @tc.desc: Test CountSubscribers with empty maps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_CountSubscribers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    size_t count = handler.CountSubscribers();
    EXPECT_EQ(count, 0UL);
}

/**
 * @tc.name: KeySubscriberHandlerTest_CountSubscribers_002
 * @tc.desc: Test CountSubscribers with subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_CountSubscribers_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto keyOption = std::make_shared<KeyOption>();
    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    auto subscriber2 = std::make_shared<KeySubscriberHandler::Subscriber>(2, sess, keyOption);
    subscribers.push_back(subscriber2);
    handler.keyGestures_.insert(std::make_pair(keyOption, subscribers));
    
    size_t count = handler.CountSubscribers();
    EXPECT_EQ(count, 3UL);
}

/**
 * @tc.name: KeySubscriberHandlerTest_DumpSubscribers_001
 * @tc.desc: Test DumpSubscribers with empty collection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_DumpSubscribers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t fd = 100;
    KeySubscriberHandler::SubscriberCollection collection;
    ASSERT_NO_FATAL_FAILURE(handler.DumpSubscribers(fd, collection));
}

/**
 * @tc.name: KeySubscriberHandlerTest_PrintKeyUpLog_001
 * @tc.desc: Test PrintKeyUpLog
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_PrintKeyUpLog_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetFinalKeyDown(false);
    keyOption->SetFinalKeyDownDuration(100);
    keyOption->SetFinalKeyUpDelay(200);
    std::set<int32_t> preKeys = {1, 2, 3};
    keyOption->SetPreKeys(preKeys);
    auto subscriber = std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    ASSERT_NO_FATAL_FAILURE(handler.PrintKeyUpLog(subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberTimer_006
 * @tc.desc: Test RemoveSubscriberTimer with empty subscriberMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberTimer_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.SetPressed(true);
    keyEvent->keys_.push_back(item);
    ASSERT_NO_FATAL_FAILURE(handler.RemoveSubscriberTimer(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_010
 * @tc.desc: Test HandleKeyDown with preKeys match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_010, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = true;
    keyOption->finalKey_ = KeyEvent::KEYCODE_C;
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_A, KeyEvent::KEYCODE_B};
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKeyDownDuration(0);
    
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_C);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    
    bool ret = handler.HandleKeyDown(keyEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_007
 * @tc.desc: Test HandleKeyUp with duration check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = false;
    keyOption->finalKey_ = KeyEvent::KEYCODE_C;
    keyOption->finalKeyDownDuration_ = 100;
    
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_C);
    item.SetPressed(false);
    item.downTime_ = 1000;
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(2000);
    
    bool ret = handler.HandleKeyUp(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_008
 * @tc.desc: Test HandleKeyUp with duration exceeding threshold
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_008, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = false;
    keyOption->finalKey_ = KeyEvent::KEYCODE_D;
    keyOption->finalKeyDownDuration_ = 100;
    
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_D);
    item.SetPressed(false);
    item.downTime_ = 1000;
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_D);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(5000);
    
    bool ret = handler.HandleKeyUp(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownRightNow_006
 * @tc.desc: Test NotifyKeyDownRightNow with empty subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownRightNow_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownRightNow(keyEvent, subscribers, false, handled));
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_010
 * @tc.desc: Test NotifyKeyDownDelay with empty subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_010, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownDelay(keyEvent, subscribers, handled));
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyUpSubscriber_003
 * @tc.desc: Test NotifyKeyUpSubscriber with empty subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyUpSubscriber_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDelay_007
 * @tc.desc: Test HandleKeyUpWithDelay with zero delay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDelay_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyUpDelay(0);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyUpWithDelay(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_RemoveSubscriberTimer_005
 * @tc.desc: Test RemoveSubscriberTimer with empty subscriberMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_RemoveSubscriberTimer_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.SetPressed(true);
    keyEvent->keys_.push_back(item);
    ASSERT_NO_FATAL_FAILURE(handler.RemoveSubscriberTimer(keyEvent));
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDown_011
 * @tc.desc: Test HandleKeyDown with preKeys match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDown_011, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = true;
    keyOption->finalKey_ = KeyEvent::KEYCODE_C;
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_A, KeyEvent::KEYCODE_B};
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKeyDownDuration(0);
    
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_C);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    
    bool ret = handler.HandleKeyDown(keyEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_010
 * @tc.desc: Test HandleKeyUp with duration check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_010, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = false;
    keyOption->finalKey_ = KeyEvent::KEYCODE_C;
    keyOption->finalKeyDownDuration_ = 100;
    
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_C);
    item.SetPressed(false);
    item.downTime_ = 1000;
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(2000);
    
    bool ret = handler.HandleKeyUp(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUp_006
 * @tc.desc: Test HandleKeyUp with duration exceeding threshold
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUp_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->isFinalKeyDown_ = false;
    keyOption->finalKey_ = KeyEvent::KEYCODE_D;
    keyOption->finalKeyDownDuration_ = 100;
    
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.subscriberMap_.insert(std::make_pair(keyOption, subscribers));
    
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_D);
    item.SetPressed(false);
    item.downTime_ = 1000;
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_D);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(5000);
    
    bool ret = handler.HandleKeyUp(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownRightNow_005
 * @tc.desc: Test NotifyKeyDownRightNow with empty subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownRightNow_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownRightNow(keyEvent, subscribers, false, handled));
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyDownDelay_008
 * @tc.desc: Test NotifyKeyDownDelay with empty subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyDownDelay_008, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyDownDelay(keyEvent, subscribers, handled));
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_NotifyKeyUpSubscriber_002
 * @tc.desc: Test NotifyKeyUpSubscriber with empty subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_NotifyKeyUpSubscriber_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::list<std::shared_ptr<KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    ASSERT_NO_FATAL_FAILURE(handler.NotifyKeyUpSubscriber(keyEvent, subscribers, handled));
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDelay_005
 * @tc.desc: Test HandleKeyUpWithDelay with zero delay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDelay_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyUpDelay(0);
    std::shared_ptr<KeySubscriberHandler::Subscriber> subscriber =
        std::make_shared<KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyUpWithDelay(keyEvent, subscriber));
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessKeyEvent_001
 * @tc.desc: Test ProcessKeyEvent with DOWN action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessKeyEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    
    bool result = handler.ProcessKeyEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessKeyEvent_002
 * @tc.desc: Test ProcessKeyEvent with UP action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessKeyEvent_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    
    bool result = handler.ProcessKeyEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessKeyEvent_003
 * @tc.desc: Test ProcessKeyEvent with CANCEL action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessKeyEvent_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    
    bool result = handler.ProcessKeyEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessKeyEvent_004
 * @tc.desc: Test ProcessKeyEvent with power key up and skip flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessKeyEvent_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    handler.needSkipPowerKeyUp_ = true;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    
    bool result = handler.ProcessKeyEvent(keyEvent);
    EXPECT_TRUE(result);
    EXPECT_FALSE(handler.needSkipPowerKeyUp_);
}

/**
 * @tc.name: KeySubscriberHandlerTest_CloneKeyEvent_002
 * @tc.desc: Test CloneKeyEvent with valid keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_CloneKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    
    EXPECT_TRUE(handler.CloneKeyEvent(keyEvent));
    ASSERT_NE(handler.keyEvent_, nullptr);
    EXPECT_EQ(handler.keyEvent_->GetKeyCode(), KeyEvent::KEYCODE_POWER);
}

/**
 * @tc.name: KeySubscriberHandlerTest_CloneKeyEvent_003
 * @tc.desc: Test CloneKeyEvent with null keyEvent_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_CloneKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    
    handler.keyEvent_ = nullptr;
    EXPECT_TRUE(handler.CloneKeyEvent(keyEvent));
    ASSERT_NE(handler.keyEvent_, nullptr);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsRepeatedKeyEvent_001
 * @tc.desc: Test IsRepeatedKeyEvent with different key codes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsRepeatedKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent1 = KeyEvent::Create();
    std::shared_ptr<KeyEvent> keyEvent2 = KeyEvent::Create();
    ASSERT_NE(keyEvent1, nullptr);
    ASSERT_NE(keyEvent2, nullptr);
    
    keyEvent1->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent2->SetKeyCode(KeyEvent::KEYCODE_B);
    
    EXPECT_FALSE(handler.IsRepeatedKeyEvent(keyEvent1));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsRepeatedKeyEvent_002
 * @tc.desc: Test IsRepeatedKeyEvent with same key code but different actions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsRepeatedKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    handler.hasEventExecuting_ = true;
    std::shared_ptr<KeyEvent> keyEvent1 = KeyEvent::Create();
    std::shared_ptr<KeyEvent> keyEvent2 = KeyEvent::Create();
    ASSERT_NE(keyEvent1, nullptr);
    ASSERT_NE(keyEvent2, nullptr);
    
    keyEvent1->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent2->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    handler.keyEvent_ = keyEvent1;
    EXPECT_FALSE(handler.IsRepeatedKeyEvent(keyEvent2));
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsRepeatedKeyEvent_003
 * @tc.desc: Test IsRepeatedKeyEvent with identical key events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsRepeatedKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    handler.hasEventExecuting_ = true;
    std::shared_ptr<KeyEvent> keyEvent1 = KeyEvent::Create();
    std::shared_ptr<KeyEvent> keyEvent2 = KeyEvent::Create();
    ASSERT_NE(keyEvent1, nullptr);
    ASSERT_NE(keyEvent2, nullptr);
    
    keyEvent1->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent1->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent2->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent2->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent1->AddKeyItem(item);
    keyEvent2->AddKeyItem(item);
    
    handler.keyEvent_ = keyEvent1;
    EXPECT_TRUE(handler.IsRepeatedKeyEvent(keyEvent2));
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddSubscriber_001
 * @tc.desc: Test AddSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddSubscriber_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(
        subscribeId, sess, nullptr);
    ASSERT_NE(subscriber, nullptr);
    
    std::shared_ptr<KeyOption> keyOption = nullptr;
    auto ret = handler.AddSubscriber(subscriber, keyOption, true);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddSubscriber_002
 * @tc.desc: Test AddSubscriber with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddSubscriber_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId1 = 1;
    int32_t subscribeId2 = 2;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    auto keyOption1 = std::make_shared<KeyOption>();
    ASSERT_NE(keyOption1, nullptr);
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption1->SetFinalKeyDown(true);
    keyOption1->SetFinalKeyDownDuration(100);
    
    auto keyOption2 = std::make_shared<KeyOption>();
    ASSERT_NE(keyOption2, nullptr);
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption2->SetFinalKeyDown(true);
    keyOption2->SetFinalKeyDownDuration(100);
    auto subscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(
        subscribeId1, sess, keyOption1);
    ASSERT_NE(subscriber1, nullptr);
    
    auto subscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(
        subscribeId2, sess, keyOption2);
    ASSERT_NE(subscriber2, nullptr);

    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber1);

    subscriber1->timerId_ = -1;
    subscriber2->timerId_ = -1;

    ASSERT_NO_FATAL_FAILURE(handler.ClearSubscriberTimer(subscribers));

    ASSERT_EQ(subscriber1->timerId_, -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_AddSubscriber_003
 * @tc.desc: Test AddSubscriber with null subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_AddSubscriber_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    
    auto keyOption = std::make_shared<KeyOption>();
    ASSERT_NE(keyOption, nullptr);

    std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber> subscriber = nullptr;
    auto ret = handler.AddSubscriber(subscriber, keyOption, true);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ClearSubscriberTimer_006
 * @tc.desc: Test ClearSubscriberTimer with multiple subscribers safely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ClearSubscriberTimer_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeySubscriberHandler handler;
    int32_t subscribeId = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    
    auto keyOption1 = std::make_shared<KeyOption>();
    ASSERT_NE(keyOption1, nullptr);
    keyOption1->SetFinalKey(KeyEvent::KEYCODE_A);
    
    auto keyOption2 = std::make_shared<KeyOption>();
    ASSERT_NE(keyOption2, nullptr);
    keyOption2->SetFinalKey(KeyEvent::KEYCODE_B);
    
    auto subscriber1 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(
        subscribeId, sess, keyOption1);
    ASSERT_NE(subscriber1, nullptr);
    
    auto subscriber2 = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(
        subscribeId + 1, sess, keyOption2);
    ASSERT_NE(subscriber2, nullptr);
    
    subscriber1->timerId_ = -1;
    subscriber2->timerId_ = -1;
    
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber1);
    subscribers.push_back(subscriber2);
    
    ASSERT_NO_FATAL_FAILURE(handler.ClearSubscriberTimer(subscribers));

    ASSERT_EQ(subscriber1->timerId_, -1);
    ASSERT_EQ(subscriber2->timerId_, -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDownForPressedType_001
 * @tc.desc: Test HandleKeyDownForPressedType with keyCode mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDownForPressedType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    int32_t keyCode = KeyEvent::KEYCODE_B;
    std::vector<int32_t> pressedKeys;
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    handler.HandleKeyDownForPressedType(keyEvent, keyCode, pressedKeys, keyOption, subscribers, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDownForPressedType_002
 * @tc.desc: Test HandleKeyDownForPressedType with preKeys mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDownForPressedType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(preKeys);
    int32_t keyCode = KeyEvent::KEYCODE_A;
    std::vector<int32_t> pressedKeys = {KeyEvent::KEYCODE_SHIFT_LEFT};
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    handler.HandleKeyDownForPressedType(keyEvent, keyCode, pressedKeys, keyOption, subscribers, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDownForPressedType_003
 * @tc.desc: Test HandleKeyDownForPressedType with matching and foreground exits
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDownForPressedType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys;
    keyOption->SetPreKeys(preKeys);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    int32_t keyCode = KeyEvent::KEYCODE_A;
    std::vector<int32_t> pressedKeys;
    handler.isForegroundExits_ = true;
    bool handled = false;
    handler.HandleKeyDownForPressedType(keyEvent, keyCode, pressedKeys, keyOption, subscribers, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDownForPressedType_004
 * @tc.desc: Test HandleKeyDownForPressedType with null session in subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDownForPressedType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys;
    keyOption->SetPreKeys(preKeys);
    SessionPtr sess;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    int32_t keyCode = KeyEvent::KEYCODE_A;
    std::vector<int32_t> pressedKeys;
    handler.isForegroundExits_ = true;
    bool handled = false;
    handler.HandleKeyDownForPressedType(keyEvent, keyCode, pressedKeys, keyOption, subscribers, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyDownForPressedType_005
 * @tc.desc: Test HandleKeyDownForPressedType not foreground and not power key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyDownForPressedType_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys;
    keyOption->SetPreKeys(preKeys);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    int32_t keyCode = KeyEvent::KEYCODE_A;
    std::vector<int32_t> pressedKeys;
    handler.isForegroundExits_ = false;
    handler.foregroundPids_.clear();
    bool handled = false;
    handler.HandleKeyDownForPressedType(keyEvent, keyCode, pressedKeys, keyOption, subscribers, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpForPressedType_001
 * @tc.desc: Test HandleKeyUpForPressedType with keyCode matching finalKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpForPressedType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    int32_t keyCode = KeyEvent::KEYCODE_A;
    bool handled = false;
    handler.HandleKeyUpForPressedType(keyEvent, keyCode, keyOption, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpForPressedType_002
 * @tc.desc: Test HandleKeyUpForPressedType with keyCode in preKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpForPressedType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(preKeys);
    int32_t keyCode = KeyEvent::KEYCODE_CTRL_LEFT;
    bool handled = false;
    handler.HandleKeyUpForPressedType(keyEvent, keyCode, keyOption, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpForPressedType_003
 * @tc.desc: Test HandleKeyUpForPressedType with keyCode not matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpForPressedType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(preKeys);
    int32_t keyCode = KeyEvent::KEYCODE_B;
    bool handled = false;
    handler.HandleKeyUpForPressedType(keyEvent, keyCode, keyOption, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_001
 * @tc.desc: Test HandleKeyUpWithDurationCheck with duration <= 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDownDuration(0);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    bool handled = false;
    bool ret = handler.HandleKeyUpWithDurationCheck(keyEvent, keyOption, subscribers, handled);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_002
 * @tc.desc: Test HandleKeyUpWithDurationCheck with keyItem nullopt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDownDuration(100);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    bool ret = handler.HandleKeyUpWithDurationCheck(keyEvent, keyOption, subscribers, handled);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_003
 * @tc.desc: Test HandleKeyUpWithDurationCheck with time check failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetActionTime(200000);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.downTime_ = 0;
    keyEvent->AddKeyItem(item);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDownDuration(100);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool handled = false;
    bool ret = handler.HandleKeyUpWithDurationCheck(keyEvent, keyOption, subscribers, handled);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_004
 * @tc.desc: Test HandleKeyUpWithDurationCheck with time check passed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_HandleKeyUpWithDurationCheck_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetActionTime(50000);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.downTime_ = 0;
    keyEvent->AddKeyItem(item);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKeyDownDuration(100);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    handler.isForegroundExits_ = true;
    bool handled = false;
    bool ret = handler.HandleKeyUpWithDurationCheck(keyEvent, keyOption, subscribers, handled);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessAllReleasedComboActivated_001
 * @tc.desc: Test ProcessAllReleasedComboActivated with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessAllReleasedComboActivated_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    auto keyOption = std::make_shared<KeyOption>();
    SessionPtr sess;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    bool handled = false;
    handler.ProcessAllReleasedComboActivated(keyEvent, keyOption, subscriber, handled);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessAllReleasedComboActivated_002
 * @tc.desc: Test ProcessAllReleasedComboActivated with foreground match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessAllReleasedComboActivated_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    auto keyOption = std::make_shared<KeyOption>();
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    handler.isForegroundExits_ = true;
    bool handled = false;
    handler.ProcessAllReleasedComboActivated(keyEvent, keyOption, subscriber, handled);
    EXPECT_TRUE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessAllReleasedComboActivated_003
 * @tc.desc: Test ProcessAllReleasedComboActivated with KEY_ACTION_UP and all keys released
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessAllReleasedComboActivated_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t subscribeId = 10;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    auto &state = handler.allReleasedStates_[subscribeId];
    state.comboActivated = true;
    state.pressedComboKeys.insert(KeyEvent::KEYCODE_A);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    handler.isForegroundExits_ = true;
    bool handled = false;
    handler.ProcessAllReleasedComboActivated(keyEvent, keyOption, subscriber, handled);
    EXPECT_TRUE(handled);
    EXPECT_TRUE(state.pressedComboKeys.empty());
    EXPECT_FALSE(state.comboActivated);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_001
 * @tc.desc: Test ProcessAllReleasedComboActivate with preKeys mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(preKeys);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    bool handled = false;
    bool ret = handler.ProcessAllReleasedComboActivate(keyEvent, keyOption, subscriber, handled);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(handled);
    auto iter = handler.allReleasedStates_.find(1);
    EXPECT_EQ(iter, handler.allReleasedStates_.end());
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_002
 * @tc.desc: Test ProcessAllReleasedComboActivate with successful activation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(preKeys);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    int32_t subscribeId = 1;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    item.pressed_ = true;
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.pressed_ = true;
    keyEvent->AddKeyItem(item);
    handler.isForegroundExits_ = true;
    bool handled = false;
    bool ret = handler.ProcessAllReleasedComboActivate(keyEvent, keyOption, subscriber, handled);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(handled);
    auto iter = handler.allReleasedStates_.find(subscribeId);
    ASSERT_NE(iter, handler.allReleasedStates_.end());
    EXPECT_TRUE(iter->second.comboActivated);
    EXPECT_EQ(iter->second.pressedComboKeys.size(), 2u);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_003
 * @tc.desc: Test ProcessAllReleasedComboActivate with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    SessionPtr sess;
    int32_t subscribeId = 1;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    handler.isForegroundExits_ = true;
    bool handled = false;
    bool ret = handler.ProcessAllReleasedComboActivate(keyEvent, keyOption, subscriber, handled);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(handled);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_004
 * @tc.desc: Test ProcessAllReleasedComboActivate with duration check and keyItem nullopt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ProcessAllReleasedComboActivate_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    keyOption->SetFinalKeyDownDuration(100);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(1, sess, keyOption);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.pressed_ = true;
    keyEvent->AddKeyItem(item);
    bool handled = false;
    bool ret = handler.ProcessAllReleasedComboActivate(keyEvent, keyOption, subscriber, handled);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ShouldProcessAllReleasedRepeat_001
 * @tc.desc: Test ShouldProcessAllReleasedRepeat with keyCode not in combo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ShouldProcessAllReleasedRepeat_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t keyCode = KeyEvent::KEYCODE_B;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    std::set<int32_t> preKeys = {KeyEvent::KEYCODE_CTRL_LEFT};
    keyOption->SetPreKeys(preKeys);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    bool ret = handler.ShouldProcessAllReleasedRepeat(keyCode, keyOption, subscribers);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ShouldProcessAllReleasedRepeat_002
 * @tc.desc: Test ShouldProcessAllReleasedRepeat with combo key but no activated state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ShouldProcessAllReleasedRepeat_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t keyCode = KeyEvent::KEYCODE_A;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    int32_t subscribeId = 1;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    auto &state = handler.allReleasedStates_[subscribeId];
    state.comboActivated = false;
    bool ret = handler.ShouldProcessAllReleasedRepeat(keyCode, keyOption, subscribers);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeySubscriberHandlerTest_ShouldProcessAllReleasedRepeat_003
 * @tc.desc: Test ShouldProcessAllReleasedRepeat with combo activated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_ShouldProcessAllReleasedRepeat_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeySubscriberHandler handler;
    int32_t keyCode = KeyEvent::KEYCODE_A;
    auto keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_A);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    ASSERT_NE(sess, nullptr);
    int32_t subscribeId = 1;
    auto subscriber = std::make_shared<OHOS::MMI::KeySubscriberHandler::Subscriber>(subscribeId, sess, keyOption);
    std::list<std::shared_ptr<OHOS::MMI::KeySubscriberHandler::Subscriber>> subscribers;
    subscribers.push_back(subscriber);
    auto &state = handler.allReleasedStates_[subscribeId];
    state.comboActivated = true;
    bool ret = handler.ShouldProcessAllReleasedRepeat(keyCode, keyOption, subscribers);
    EXPECT_TRUE(ret);
}
} // namespace MMI
} // namespace OHOS
