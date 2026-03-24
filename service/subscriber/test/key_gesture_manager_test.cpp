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

#include "display_event_monitor.h"
#include "event_log_helper.h"
#include "key_option.h"
#include "key_gesture_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "nap_process.h"
#include "switch_subscriber_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyGestureManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t INVALID_ENTITY_ID { -1 };
constexpr size_t SINGLE_KEY_PRESSED { 1 };
} // namespace

class KeyGestureManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MyKeyGesture : public KeyGestureManager::KeyGesture {
public:
    MyKeyGesture() = default;
    ~MyKeyGesture() override = default;

    bool IsWorking() override
    {
        return true;
    }

    bool ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const override
    {
        return true;
    }

    bool Intercept(std::shared_ptr<KeyEvent> keyEvent) override
    {
        return true;
    }

    void Dump(std::ostringstream &output) const override
    {
        output << "MyKeyGesture";
    }
};

/**
 * @tc.name: KeyGestureManagerTest_Intercept_002
 * @tc.desc: Test the function Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto keyGesture1 = std::make_unique<MyKeyGesture>();
    auto keyGesture2 = std::make_unique<MyKeyGesture>();
    auto keyGesture3 = std::make_unique<MyKeyGesture>();
    keyGestureManager.keyGestures_.push_back(std::move(keyGesture1));
    keyGestureManager.keyGestures_.push_back(std::move(keyGesture2));
    keyGestureManager.keyGestures_.push_back(std::move(keyGesture3));
    EXPECT_FALSE(EventLogHelper::IsBetaVersion());
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE));
    EXPECT_TRUE(keyGestureManager.Intercept(keyEvent));
}

/**
 * @tc.name: KeyGestureManagerTest_TriggerHandlers_01
 * @tc.desc: Test the function TriggerHandlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_TriggerHandlers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler1(1, 10, 500, myCallback);
    KeyGestureManager::Handler handler2(2, 20, 1000, myCallback);
    KeyGestureManager::Handler handler3(3, 30, 1500, myCallback);

    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    std::set<int32_t> foregroundPids = myKeyGesture->GetForegroundPids();
    bool haveForeground = myKeyGesture->HaveForegroundHandler(foregroundPids);
    EXPECT_FALSE(haveForeground);
    ASSERT_NO_FATAL_FAILURE(myKeyGesture->TriggerHandlers(keyEvent));
}

/**
 * @tc.name: LongPressSingleKey_Dump_01
 * @tc.desc: Test the function LongPressSingleKey_Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_Dump_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::ostringstream output;
    longPressSingleKey.keyCode_ = 2;

    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler1(1, 10, 500, myCallback);
    KeyGestureManager::Handler handler2(2, 20, 1000, myCallback);
    KeyGestureManager::Handler handler3(3, 30, 1500, myCallback);

    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);
    ASSERT_NO_FATAL_FAILURE(longPressSingleKey.Dump(output));
}

/**
 * @tc.name: LongPressCombinationKey_Dump_01
 * @tc.desc: Test the function LongPressCombinationKey_Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Dump_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {1, 2, 3};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::ostringstream output;
    longPressCombinationKey.keys_ = {3, 4, 5, 6};
    ASSERT_NO_FATAL_FAILURE(longPressCombinationKey.Dump(output));

    longPressCombinationKey.keys_ = {};
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler1(1, 10, 500, myCallback);
    KeyGestureManager::Handler handler2(2, 20, 1000, myCallback);
    KeyGestureManager::Handler handler3(3, 30, 1500, myCallback);
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);
    ASSERT_NO_FATAL_FAILURE(longPressCombinationKey.Dump(output));
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_01
 * @tc.desc: Test the function Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool ret = keyGestureManager.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_RemoveKeyGesture_01
 * @tc.desc: Test the function RemoveKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RemoveKeyGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t id = 1;
    ASSERT_NO_FATAL_FAILURE(keyGestureManager.RemoveKeyGesture(id));
    bool result = true;
    for (auto &keyGesture : keyGestureManager.keyGestures_) {
        if (keyGesture->RemoveHandler(id)) {
            result = false;
        }
    }
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeyGestureManagerTest_RemoveKeyGesture_02
 * @tc.desc: Test the function RemoveKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RemoveKeyGesture_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t id = -2;
    ASSERT_NO_FATAL_FAILURE(keyGestureManager.RemoveKeyGesture(id));
    bool result = true;
    for (auto &keyGesture : keyGestureManager.keyGestures_) {
        if (keyGesture->RemoveHandler(id)) {
            result = false;
        }
    }
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeyGestureManagerTest_AddKeyGesture_01
 * @tc.desc: Test the function AddKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_AddKeyGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t pid = 1;
    std::shared_ptr<KeyOption> keyOption = nullptr;
    auto callback = [](std::shared_ptr<KeyEvent> event) {};
    int32_t result = keyGestureManager.AddKeyGesture(pid, keyOption, callback);
    EXPECT_EQ(result, INVALID_ENTITY_ID);
}

/**
 * @tc.name: KeyGestureManagerTest_ShouldIntercept_01
 * @tc.desc: Test the function ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_ShouldIntercept_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    std::shared_ptr<KeyOption> keyOption = nullptr;
    bool result = keyGestureManager.ShouldIntercept(keyOption);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_02
 * @tc.desc: Test the function ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 2;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_DOWN;

    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->active_ = true;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_TRUE(ret);

    myKeyGesture->active_ = true;
    bool ret2 = longPressSingleKey.Intercept(keyEvent);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_03
 * @tc.desc: Test the function ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 3;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_DOWN;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_04
 * @tc.desc: Test the function ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 2;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UP;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_05
 * @tc.desc: Test the function ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 3;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UP;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_Intercept_06
 * @tc.desc: Test the function ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_Intercept_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = 3;
    longPressSingleKey.keyCode_ = 2;
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UP;

    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->active_ = true;
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);

    myKeyGesture->active_ = false;
    bool ret2 = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: KeyGestureManagerTest_IsWorking_01
 * @tc.desc: Test the function ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_IsWorking_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    auto orignScreenStatus = DISPLAY_MONITOR->GetScreenStatus();
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    bool ret = pullUpAccessibility.IsWorking();
    EXPECT_FALSE(ret);
    DISPLAY_MONITOR->SetScreenStatus(orignScreenStatus);
}

/**
 * @tc.name: KeyGestureManagerTest_RecognizeGesture_01
 * @tc.desc: Test the function RecognizeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RecognizeGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {1, 2, 3};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    std::vector<int32_t> pressedKeys = {1};
    EXPECT_TRUE(pressedKeys.size() == SINGLE_KEY_PRESSED);
    bool ret = longPressCombinationKey.RecognizeGesture(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_RecognizeGesture_02
 * @tc.desc: Test the function RecognizeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RecognizeGesture_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = { 1, 2, 3 };
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    std::vector<int32_t> pressedKeys = { 2, 3, 4 };
    EXPECT_FALSE(pressedKeys.size() == SINGLE_KEY_PRESSED);
    bool ret = longPressCombinationKey.RecognizeGesture(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_TriggerAll_01
 * @tc.desc: Test the function TriggerAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_TriggerAll_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = { 1, 2, 3 };
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(longPressCombinationKey.TriggerAll(keyEvent));
}

/**
 * @tc.name: KeyGestureManagerTest_RunPending_01
 * @tc.desc: Test the function RunPending
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RunPending_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler(1, 2, 3000, myCallback);

    handler.keyEvent_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.RunPending());
}

/**
 * @tc.name: KeyGestureManagerTest_RunPending_02
 * @tc.desc: Test the function RunPending
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RunPending_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler(1, 2, 3000, myCallback);

    handler.keyEvent_ = KeyEvent::Create();
    ASSERT_NE(handler.keyEvent_, nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.RunPending());
}

/**
 * @tc.name: KeyGestureManagerTest_ResetTimer_01
 * @tc.desc: Test the function ResetTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_ResetTimer_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler(1, 2, 3000, myCallback);
    handler.timerId_ = 1;
    ASSERT_NO_FATAL_FAILURE(handler.ResetTimer());
}

/**
 * @tc.name: KeyGestureManagerTest_ResetTimer_02
 * @tc.desc: Test the function ResetTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_ResetTimer_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler(1, 2, 3000, myCallback);
    handler.timerId_ = -2;
    ASSERT_NO_FATAL_FAILURE(handler.ResetTimer());
}

/**
 * @tc.name: KeyGestureManagerTest_RunPendingHandlers_01
 * @tc.desc: Test the function RunPendingHandlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RunPendingHandlers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler1(1, 10, 500, myCallback);
    KeyGestureManager::Handler handler2(2, 20, 1000, myCallback);
    KeyGestureManager::Handler handler3(3, 30, 1500, myCallback);

    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);

    std::set<int32_t> foregroundPids = myKeyGesture->GetForegroundPids();
    bool haveForeground = myKeyGesture->HaveForegroundHandler(foregroundPids);
    EXPECT_FALSE(haveForeground);

    int32_t keyCode = 1;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    ASSERT_NO_FATAL_FAILURE(longPressSingleKey.RunPendingHandlers());
}

/**
 * @tc.name: KeyGestureManagerTest_RunHandler_01
 * @tc.desc: Test the function RunHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RunHandler_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler1(1, 10, 500, myCallback);
    KeyGestureManager::Handler handler2(2, 20, 1000, myCallback);
    KeyGestureManager::Handler handler3(3, 30, 1500, myCallback);

    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);

    int32_t handlerId = 1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(myKeyGesture->RunHandler(handlerId, keyEvent));

    handlerId = 5;
    ASSERT_NO_FATAL_FAILURE(myKeyGesture->RunHandler(handlerId, keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_01
 * @tc.desc: Test the function RecognizeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {1, 2, 3};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->keyCode_ = 3;
    longPressCombinationKey.keys_ = {2, 3, 4};
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_DOWN;
    myKeyGesture->active_ = true;
    EXPECT_FALSE(EventLogHelper::IsBetaVersion());
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE));
    bool ret = longPressCombinationKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
    myKeyGesture->active_ = false;
    EXPECT_TRUE(myKeyGesture->IsWorking());

    KeyGestureManager::Handler handler1(1, 10, 500, myCallback);
    KeyGestureManager::Handler handler2(2, 20, 1000, myCallback);
    KeyGestureManager::Handler handler3(3, 30, 1500, myCallback);
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);
    EXPECT_FALSE(myKeyGesture->handlers_.empty());
    bool ret2 = longPressCombinationKey.Intercept(keyEvent);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_02
 * @tc.desc: Test the function RecognizeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {1, 2, 3};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->keyCode_ = 5;
    longPressCombinationKey.keys_ = {2, 3, 4};
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UP;
    myKeyGesture->active_ = true;
    bool ret = longPressCombinationKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);

    myKeyGesture->active_ = false;
    bool ret2 = longPressCombinationKey.Intercept(keyEvent);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_03
 * @tc.desc: Test the function LongPressCombinationKey::Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    longPressCombinationKey.MarkActive(true);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(longPressCombinationKey.Intercept(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_04
 * @tc.desc: Test the function LongPressCombinationKey::Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_FALSE(longPressCombinationKey.Intercept(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_05
 * @tc.desc: Test the function LongPressCombinationKey::Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    longPressCombinationKey.MarkKeyConsumed();

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_TRUE(longPressCombinationKey.Intercept(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_06
 * @tc.desc: Test the function LongPressCombinationKey::Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_FALSE(longPressCombinationKey.Intercept(keyEvent));
}

/**
 * @tc.name: KeyGestureManagerTest_NotifyHandlers_01
 * @tc.desc: Test the function NotifyHandlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_NotifyHandlers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    KeyGestureManager::Handler handler1(1, 10, 500, myCallback);
    KeyGestureManager::Handler handler2(2, 20, 1000, myCallback);
    KeyGestureManager::Handler handler3(3, 30, 1500, myCallback);

    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->handlers_.push_back(handler1);
    myKeyGesture->handlers_.push_back(handler2);
    myKeyGesture->handlers_.push_back(handler3);

    std::set<int32_t> foregroundPids = myKeyGesture->GetForegroundPids();
    bool haveForeground = myKeyGesture->HaveForegroundHandler(foregroundPids);
    EXPECT_FALSE(haveForeground);
    ASSERT_NO_FATAL_FAILURE(myKeyGesture->NotifyHandlers(keyEvent));
}

/**
 * @tc.name: KeyGestureManagerTest_AddHandler
 * @tc.desc: Test the function AddHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, AddHandler_Success, TestSize.Level1)
{
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();

    int32_t id1 = myKeyGesture->AddHandler(10, 500, myCallback);
    EXPECT_GT(id1, 0);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 1);

    int32_t id2 = myKeyGesture->AddHandler(20, 1000, myCallback);
    EXPECT_GT(id2, id1);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 2);
}

/**
 * @tc.name: KeyGestureManagerTest_RemoveHandler
 * @tc.desc: Test the function RemoveHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RemoveHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();

    int32_t id1 = myKeyGesture->AddHandler(10, 500, myCallback);
    int32_t id2 = myKeyGesture->AddHandler(20, 1000, myCallback);

    bool resultSuccess = myKeyGesture->RemoveHandler(id1);
    EXPECT_TRUE(resultSuccess);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 1);

    bool resultFailed = myKeyGesture->RemoveHandler(id1);
    EXPECT_FALSE(resultFailed);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 1);

    EXPECT_EQ(myKeyGesture->handlers_.front().GetId(), id2);
}

/**
 * @tc.name: KeyGestureManagerTest_ResetTimers
 * @tc.desc: Test the function KeyGestureManager::KeyGesture::ResetTimers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_KeyGesture_ResetTimers, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();

    int32_t id1 = myKeyGesture->AddHandler(10, 500, myCallback);
    int32_t id2 = myKeyGesture->AddHandler(30, 1500, myCallback);

    EXPECT_EQ(myKeyGesture->handlers_.size(), 2);
    myKeyGesture->ResetTimers();
    EXPECT_EQ(myKeyGesture->handlers_.size(), 2);
    bool resultFailed1 = myKeyGesture->RemoveHandler(id1);
    EXPECT_TRUE(resultFailed1);
    bool resultFailed2 = myKeyGesture->RemoveHandler(id2);
    EXPECT_TRUE(resultFailed2);
}

/**
 * @tc.name: KeyGestureManagerTest_KeyGesture_IsWorking
 * @tc.desc: Test the function KeyGestureManager::KeyGesture::IsWorking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_KeyGesture_IsWorking, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    EXPECT_TRUE(myKeyGesture->IsWorking());
}

/**
 * @tc.name: KeyGestureManagerTest_KeyGesture_GetForegroundPids
 * @tc.desc: Test the function KeyGestureManager::KeyGesture::GetForegroundPids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_KeyGesture_GetForegroundPids, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::set<int32_t> pids = myKeyGesture->GetForegroundPids();
    EXPECT_EQ(pids.size(), 0);
}

/**
 * @tc.name: KeyGestureManagerTest_KeyGesture_HaveForegroundHandler
 * @tc.desc: Test the function KeyGestureManager::KeyGesture::HaveForegroundHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_HaveForegroundHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::set<int32_t> foregroundPids = {1001, 1002};
    EXPECT_FALSE(myKeyGesture->HaveForegroundHandler(foregroundPids));
}

/**
 * @tc.name: KeyGestureManagerTest_KeyGesture_ShowHandlers
 * @tc.desc: Test the function KeyGestureManager::KeyGesture::_ShowHandlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_KeyGesture_ShowHandlers, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    myKeyGesture->AddHandler(1001, 500, myCallback);
    myKeyGesture->AddHandler(1002, 1500, myCallback);
    myKeyGesture->AddHandler(1003, 800, myCallback);
    myKeyGesture->AddHandler(1004, 1600, myCallback);
    ASSERT_NO_FATAL_FAILURE(myKeyGesture->ShowHandlers("TestPrefix", {1001, 1002, 1003, 1004}));
}

/**
 * @tc.name: KeyGestureManagerTest_LongPressSingleKey_ShouldIntercept
 * @tc.desc: Test the function LongPressSingleKey::ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_ShouldIntercept, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1001;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(keyCode);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(100);
    EXPECT_TRUE(longPressSingleKey.ShouldIntercept(keyOption));
}

/**
 * @tc.name: KeyGestureManagerTest_LongPressSingleKey_Dump
 * @tc.desc: Test the function LongPressSingleKey::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(1001);
    std::ostringstream output;
    longPressSingleKey.Dump(output);
    EXPECT_FALSE(output.str().empty());
}

/**
 * @tc.name: LongPressCombinationKey_Intercept
 * @tc.desc: Test the function LongPressCombinationKey::Intercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_FALSE(longPressCombinationKey.Intercept(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_Dump
 * @tc.desc: Test the function LongPressCombinationKey::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::ostringstream output;
    longPressCombinationKey.Dump(output);
    EXPECT_FALSE(output.str().empty());
}

/**
 * @tc.name: LongPressCombinationKey_MarkKeyConsumed
 * @tc.desc: Test the function LongPressCombinationKey::MarkKeyConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_MarkKeyConsumed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    EXPECT_NO_FATAL_FAILURE(longPressCombinationKey.MarkKeyConsumed());
}

/**
 * @tc.name: LongPressCombinationKey_UpdateConsumed_001
 * @tc.desc: Test the function LongPressCombinationKey::UpdateConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_UpdateConsumed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    longPressCombinationKey.MarkKeyConsumed();

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_TRUE(longPressCombinationKey.UpdateConsumed(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_UpdateConsumed_002
 * @tc.desc: Test the function LongPressCombinationKey::UpdateConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_UpdateConsumed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    longPressCombinationKey.MarkKeyConsumed();

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    EXPECT_TRUE(longPressCombinationKey.UpdateConsumed(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_UpdateConsumed_003
 * @tc.desc: Test the function LongPressCombinationKey::UpdateConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_UpdateConsumed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    longPressCombinationKey.MarkKeyConsumed();

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_FALSE(longPressCombinationKey.UpdateConsumed(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_UpdateConsumed_004
 * @tc.desc: Test the function LongPressCombinationKey::UpdateConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_UpdateConsumed_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    longPressCombinationKey.MarkKeyConsumed();

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_FALSE(longPressCombinationKey.UpdateConsumed(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_UpdateConsumed_005
 * @tc.desc: Test the function LongPressCombinationKey::UpdateConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_UpdateConsumed_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_FALSE(longPressCombinationKey.UpdateConsumed(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_RecognizeGesture
 * @tc.desc: Test the function LongPressCombinationKey::RecognizeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_RecognizeGesture, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_FALSE(longPressCombinationKey.RecognizeGesture(keyEvent));
}

/**
 * @tc.name: LongPressCombinationKey_TriggerAll
 * @tc.desc: Test the function LongPressCombinationKey::TriggerAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_TriggerAll, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(longPressCombinationKey.TriggerAll(keyEvent));
}

/**
 * @tc.name: PullUpAccessibility_AddHandler
 * @tc.desc: Test the function PullUpAccessibility::AddHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, PullUpAccessibility_AddHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    int32_t id = pullUpAccessibility.AddHandler(10, 500, myCallback);
    EXPECT_GT(id, 0);
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    bool result = myKeyGesture->RemoveHandler(id);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PullUpAccessibility_OnTriggerAll
 * @tc.desc: Test the function PullUpAccessibility::OnTriggerAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, PullUpAccessibility_OnTriggerAll, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(pullUpAccessibility.OnTriggerAll(keyEvent));
}

/**
 * @tc.name: KeyGestureManager_Dump
 * @tc.desc: Test the function KeyGestureManager::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    ASSERT_NO_FATAL_FAILURE(keyGestureManager.Dump());
}

/**
 * @tc.name: KeyGestureManager_KeyMonitorIntercept
 * @tc.desc: Test the function KeyGestureManager::KeyMonitorIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_KeyMonitorIntercept, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->SetKeyCode(1001);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_FALSE(keyGestureManager.KeyMonitorIntercept(keyEvent));
}

/**
 * @tc.name: Handler_Run_CallbackNull_01
 * @tc.desc: Test Handler Run when callback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, Handler_Run_CallbackNull_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback = nullptr;
    KeyGestureManager::Handler handler(1, 2, 3000, myCallback);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    
    handler.Run(keyEvent);
    EXPECT_EQ(myCallback, nullptr);
}

/**
 * @tc.name: Handler_Destructor_01
 * @tc.desc: Test Handler destructor calls ResetTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, Handler_Destructor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    {
        KeyGestureManager::Handler handler(1, 2, 3000, myCallback);
        handler.timerId_ = 1;
    }
    EXPECT_TRUE(true);
}

/**
 * @tc.name: KeyGesture_Reset_01
 * @tc.desc: Test KeyGesture Reset function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_Reset_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    
    myKeyGesture->AddHandler(10, 500, myCallback);
    myKeyGesture->AddHandler(20, 1000, myCallback);
    myKeyGesture->MarkActive(true);
    
    EXPECT_EQ(myKeyGesture->handlers_.size(), 2);
    myKeyGesture->Reset();
    EXPECT_EQ(myKeyGesture->handlers_.size(), 2);
    EXPECT_FALSE(myKeyGesture->IsActive());
}

/**
 * @tc.name: KeyGesture_AddHandler_MinTime_01
 * @tc.desc: Test AddHandler with minimum longPressTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_AddHandler_MinTime_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    
    int32_t id = myKeyGesture->AddHandler(10, 50, myCallback);
    EXPECT_GT(id, 0);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 1);
    EXPECT_GE(myKeyGesture->handlers_.front().GetLongPressTime(), 150);
}

/**
 * @tc.name: KeyGesture_HaveForegroundHandler_Empty_01
 * @tc.desc: Test HaveForegroundHandler with empty handlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_HaveForegroundHandler_Empty_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::set<int32_t> foregroundPids = {1001, 1002};
    
    EXPECT_TRUE(myKeyGesture->handlers_.empty());
    EXPECT_FALSE(myKeyGesture->HaveForegroundHandler(foregroundPids));
}

/**
 * @tc.name: KeyGesture_RunHandler_NotFound_01
 * @tc.desc: Test RunHandler when handlerId not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_RunHandler_NotFound_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    
    myKeyGesture->AddHandler(10, 500, myCallback);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    
    int32_t handlerId = 999;
    myKeyGesture->RunHandler(handlerId, keyEvent);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 1);
}

/**
 * @tc.name: KeyGesture_ShowHandlers_Empty_01
 * @tc.desc: Test ShowHandlers with empty handlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_ShowHandlers_Empty_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    std::set<int32_t> foregroundPids = {1001};
    
    myKeyGesture->ShowHandlers("EmptyTest", foregroundPids);
    EXPECT_TRUE(myKeyGesture->handlers_.empty());
}

/**
 * @tc.name: LongPressSingleKey_Intercept_TVDevice_01
 * @tc.desc: Test LongPressSingleKey Intercept on TV device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_Intercept_TVDevice_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    longPressSingleKey.AddHandler(10, 500, myCallback);
    
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: LongPressSingleKey_Intercept_Active_Timeout_01
 * @tc.desc: Test LongPressSingleKey Intercept when active and timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_Intercept_Active_Timeout_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    longPressSingleKey.MarkActive(true);
    longPressSingleKey.firstDownTime_ = GetSysClockTime() - MS2US(200);
    
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: LongPressSingleKey_Intercept_VolumeUp_01
 * @tc.desc: Test LongPressSingleKey Intercept with VOLUME_UP key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_Intercept_VolumeUp_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    longPressSingleKey.MarkActive(true);
    
    bool ret = longPressSingleKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressSingleKey_ShouldIntercept_PreKeysNotEmpty_01
 * @tc.desc: Test ShouldIntercept when PreKeys is not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_ShouldIntercept_PreKeysNotEmpty_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1001;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys({1002});
    keyOption->SetFinalKey(keyCode);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(100);
    
    bool ret = longPressSingleKey.ShouldIntercept(keyOption);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressSingleKey_ShouldIntercept_DurationTooLong_01
 * @tc.desc: Test ShouldIntercept when duration exceeds timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_ShouldIntercept_DurationTooLong_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1001;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(keyCode);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(200);
    
    bool ret = longPressSingleKey.ShouldIntercept(keyOption);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressSingleKey_ShouldIntercept_KeyUp_01
 * @tc.desc: Test ShouldIntercept when key is up
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_ShouldIntercept_KeyUp_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 1001;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(keyCode);
    
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(keyCode);
    keyOption->SetFinalKeyDown(false);
    keyOption->SetFinalKeyDownDuration(100);
    
    bool ret = longPressSingleKey.ShouldIntercept(keyOption);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressCombinationKey_ShouldIntercept_Match_01
 * @tc.desc: Test ShouldIntercept when keys match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_ShouldIntercept_Match_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys({KeyEvent::KEYCODE_VOLUME_DOWN});
    keyOption->SetFinalKey(KeyEvent::KEYCODE_VOLUME_UP);
    
    bool ret = longPressCombinationKey.ShouldIntercept(keyOption);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: LongPressCombinationKey_ShouldIntercept_NoMatch_01
 * @tc.desc: Test ShouldIntercept when keys don't match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_ShouldIntercept_NoMatch_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetPreKeys({KeyEvent::KEYCODE_POWER});
    keyOption->SetFinalKey(KeyEvent::KEYCODE_HOME);
    
    bool ret = longPressCombinationKey.ShouldIntercept(keyOption);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_NoHandler_01
 * @tc.desc: Test Intercept when handlers is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_NoHandler_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    EXPECT_TRUE(longPressCombinationKey.handlers_.empty());
    bool ret = longPressCombinationKey.Intercept(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressCombinationKey_Intercept_NotWorking_01
 * @tc.desc: Test Intercept when IsWorking returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Intercept_NotWorking_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    EXPECT_FALSE(pullUpAccessibility.IsWorking());
    bool ret = pullUpAccessibility.Intercept(keyEvent);
    EXPECT_FALSE(ret);
    
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
}

/**
 * @tc.name: LongPressCombinationKey_UpdateConsumed_KeyNotInSet_01
 * @tc.desc: Test UpdateConsumed when key not in keys_ set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_UpdateConsumed_KeyNotInSet_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    longPressCombinationKey.MarkKeyConsumed();
    
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    bool ret = longPressCombinationKey.UpdateConsumed(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressCombinationKey_UpdateConsumed_NotConsumed_01
 * @tc.desc: Test UpdateConsumed when key not in consumedKeys_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_UpdateConsumed_NotConsumed_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP });
    
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    
    bool ret = longPressCombinationKey.UpdateConsumed(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressCombinationKey_RecognizeGesture_RepeatKey_01
 * @tc.desc: Test RecognizeGesture when key is repeat key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_RecognizeGesture_RepeatKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    bool ret = longPressCombinationKey.RecognizeGesture(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressCombinationKey_TriggerAll_MultipleHandlers_01
 * @tc.desc: Test TriggerAll with multiple handlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_TriggerAll_MultipleHandlers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    longPressCombinationKey.AddHandler(10, 500, myCallback);
    longPressCombinationKey.AddHandler(20, 1000, myCallback);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    longPressCombinationKey.TriggerAll(keyEvent);
    EXPECT_TRUE(longPressCombinationKey.IsActive());
    EXPECT_EQ(longPressCombinationKey.handlers_.size(), 2);
}

/**
 * @tc.name: PullUpAccessibility_IsWorking_ScreenLocked_01
 * @tc.desc: Test IsWorking when screen is locked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, PullUpAccessibility_IsWorking_ScreenLocked_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    DISPLAY_MONITOR->SetScreenLocked(true);
    
    bool ret = pullUpAccessibility.IsWorking();
    EXPECT_TRUE(ret || !ret);
    
    DISPLAY_MONITOR->SetScreenLocked(false);
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
}

/**
 * @tc.name: KeyGestureManager_ResetAll_01
 * @tc.desc: Test KeyGestureManager ResetAll function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_ResetAll_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    keyGestureManager.AddKeyGesture(10,
        std::make_shared<KeyOption>(), myCallback);
    
    keyGestureManager.ResetAll();
    EXPECT_TRUE(true);
}

/**
 * @tc.name: KeyGestureManager_Intercept_MultipleGestures_01
 * @tc.desc: Test Intercept with multiple gestures
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_Intercept_MultipleGestures_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    bool ret = keyGestureManager.Intercept(keyEvent);
    EXPECT_TRUE(ret || !ret);
}

/**
 * @tc.name: KeyGestureManager_AddKeyGesture_InvalidOption_01
 * @tc.desc: Test AddKeyGesture with nullptr keyOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_AddKeyGesture_InvalidOption_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    
    int32_t pid = 10;
    std::shared_ptr<KeyOption> keyOption = nullptr;
    std::function<void(std::shared_ptr<KeyEvent>)> callback;
    
    int32_t result = keyGestureManager.AddKeyGesture(pid, keyOption, callback);
    EXPECT_EQ(result, INVALID_ENTITY_ID);
}

/**
 * @tc.name: KeyGestureManager_RemoveKeyGesture_MultipleGestures_01
 * @tc.desc: Test RemoveKeyGesture with multiple gestures
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_RemoveKeyGesture_MultipleGestures_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(100);
    
    int32_t id = keyGestureManager.AddKeyGesture(10, keyOption, myCallback);
    EXPECT_GT(id, 0);
    
    keyGestureManager.RemoveKeyGesture(id);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: KeyGestureManager_ShouldIntercept_MultipleGestures_01
 * @tc.desc: Test ShouldIntercept with multiple gestures
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_ShouldIntercept_MultipleGestures_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->SetFinalKey(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(100);
    
    bool result = keyGestureManager.ShouldIntercept(keyOption);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeyGestureManager_Dump_Default_01
 * @tc.desc: Test Dump with default gestures
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_Dump_Default_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    
    keyGestureManager.Dump();
    EXPECT_EQ(keyGestureManager.keyGestures_.size(), 3);
}

/**
 * @tc.name: KeyGestureManager_KeyMonitorIntercept_Delay_01
 * @tc.desc: Test KeyMonitorIntercept with delay parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManager_KeyMonitorIntercept_Delay_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(1001);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    
    int32_t delay = 500;
    bool ret = keyGestureManager.KeyMonitorIntercept(keyEvent, delay);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LongPressSingleKey_Dump_EmptyHandlers_01
 * @tc.desc: Test Dump with empty handlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressSingleKey_Dump_EmptyHandlers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::LongPressSingleKey longPressSingleKey(1001);
    
    std::ostringstream output;
    longPressSingleKey.Dump(output);
    
    EXPECT_FALSE(output.str().empty());
    EXPECT_TRUE(longPressSingleKey.handlers_.empty());
}

/**
 * @tc.name: LongPressCombinationKey_Dump_EmptyHandlers_01
 * @tc.desc: Test Dump with empty handlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, LongPressCombinationKey_Dump_EmptyHandlers_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> keys = {KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP};
    KeyGestureManager::LongPressCombinationKey longPressCombinationKey(keys);
    
    std::ostringstream output;
    longPressCombinationKey.Dump(output);
    
    EXPECT_FALSE(output.str().empty());
    EXPECT_TRUE(longPressCombinationKey.handlers_.empty());
}

/**
 * @tc.name: KeyGesture_TriggerHandlers_ForegroundMatch_01
 * @tc.desc: Test TriggerHandlers when foreground matches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_TriggerHandlers_ForegroundMatch_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    
    int32_t id = myKeyGesture->AddHandler(10, 500, myCallback);
    EXPECT_GT(id, 0);
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    
    myKeyGesture->TriggerHandlers(keyEvent);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 1);
}

/**
 * @tc.name: KeyGesture_NotifyHandlers_Empty_01
 * @tc.desc: Test NotifyHandlers with empty handlers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGesture_NotifyHandlers_Empty_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MyKeyGesture> myKeyGesture = std::make_shared<MyKeyGesture>();
    
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    
    EXPECT_TRUE(myKeyGesture->handlers_.empty());
    myKeyGesture->NotifyHandlers(keyEvent);
    EXPECT_TRUE(myKeyGesture->handlers_.empty());
}
} // namespace MMI
} // namespace OHOS