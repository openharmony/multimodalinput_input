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
#include "mmi_log.h"
#include "switch_subscriber_handler.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyCommandHandlerTest" };
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
    KeySubscriberHandler keySubscriberHandler;
    auto keyEvent = KeyEvent::Create();
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
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
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
    KeySubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
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
} // namespace MMI
} // namespace OHOS
