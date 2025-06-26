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
 * @tc.desc: Test the funcation Intercept
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
 * @tc.desc: Test the funcation TriggerHandlers
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
 * @tc.desc: Test the funcation LongPressSingleKey_Dump
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
 * @tc.desc: Test the funcation LongPressCombinationKey_Dump
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
 * @tc.desc: Test the funcation Intercept
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
 * @tc.desc: Test the funcation RemoveKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RemoveKeyGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t id = 1;
    ASSERT_NO_FATAL_FAILURE(keyGestureManager.RemoveKeyGesture(id));
}

/**
 * @tc.name: KeyGestureManagerTest_RemoveKeyGesture_02
 * @tc.desc: Test the funcation RemoveKeyGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_RemoveKeyGesture_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager keyGestureManager;
    int32_t id = -2;
    ASSERT_NO_FATAL_FAILURE(keyGestureManager.RemoveKeyGesture(id));
}

/**
 * @tc.name: KeyGestureManagerTest_AddKeyGesture_01
 * @tc.desc: Test the funcation AddKeyGesture
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
 * @tc.desc: Test the funcation ShouldIntercept
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
 * @tc.desc: Test the funcation ShouldIntercept
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
 * @tc.desc: Test the funcation ShouldIntercept
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
 * @tc.desc: Test the funcation ShouldIntercept
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
 * @tc.desc: Test the funcation ShouldIntercept
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
 * @tc.desc: Test the funcation ShouldIntercept
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
 * @tc.desc: Test the funcation ShouldIntercept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyGestureManagerTest, KeyGestureManagerTest_IsWorking_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::PullUpAccessibility pullUpAccessibility;
    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
    bool ret = pullUpAccessibility.IsWorking();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyGestureManagerTest_RecognizeGesture_01
 * @tc.desc: Test the funcation RecognizeGesture
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
 * @tc.desc: Test the funcation RecognizeGesture
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
 * @tc.desc: Test the funcation TriggerAll
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
 * @tc.desc: Test the funcation RunPending
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
 * @tc.desc: Test the funcation RunPending
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
 * @tc.desc: Test the funcation ResetTimer
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
 * @tc.desc: Test the funcation ResetTimer
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
 * @tc.desc: Test the funcation RunPendingHandlers
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
 * @tc.desc: Test the funcation RunHandler
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
 * @tc.desc: Test the funcation RecognizeGesture
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
 * @tc.desc: Test the funcation RecognizeGesture
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
 * @tc.name: KeyGestureManagerTest_NotifyHandlers_01
 * @tc.desc: Test the funcation NotifyHandlers
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
 * @tc.desc: Test the funcation AddHandler
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
 * @tc.desc: Test the funcation RemoveHandler
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

    bool resultfailed = myKeyGesture->RemoveHandler(id1);
    EXPECT_FALSE(resultfailed);
    EXPECT_EQ(myKeyGesture->handlers_.size(), 1);

    EXPECT_EQ(myKeyGesture->handlers_.front().GetId(), id2);
}

/**
 * @tc.name: KeyGestureManagerTest_ResetTimers
 * @tc.desc: Test the funcation KeyGestureManager::KeyGesture::ResetTimers
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
    bool resultfailed1 = myKeyGesture->RemoveHandler(id1);
    EXPECT_TRUE(resultfailed1);
    bool resultfailed2 = myKeyGesture->RemoveHandler(id2);
    EXPECT_TRUE(resultfailed2);

}

/**
 * @tc.name: KeyGestureManagerTest_KeyGesture_IsWorking
 * @tc.desc: Test the funcation KeyGestureManager::KeyGesture::IsWorking
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
 * @tc.desc: Test the funcation KeyGestureManager::KeyGesture::GetForegroundPids
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
 * @tc.desc: Test the funcation KeyGestureManager::KeyGesture::HaveForegroundHandler
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
 * @tc.desc: Test the funcation KeyGestureManager::KeyGesture::_ShowHandlers
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
 * @tc.desc: Test the funcation LongPressSingleKey::ShouldIntercept
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
 * @tc.desc: Test the funcation LongPressSingleKey::Dump
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
 * @tc.desc: Test the funcation LongPressCombinationKey::Intercept
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
 * @tc.desc: Test the funcation LongPressCombinationKey::Dump
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
 * @tc.name: LongPressCombinationKey_RecognizeGesture
 * @tc.desc: Test the funcation LongPressCombinationKey::RecognizeGesture
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
 * @tc.desc: Test the funcation LongPressCombinationKey::TriggerAll
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
 * @tc.desc: Test the funcation PullUpAccessibility::AddHandler
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
}

/**
 * @tc.name: PullUpAccessibility_OnTriggerAll
 * @tc.desc: Test the funcation PullUpAccessibility::OnTriggerAll
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
 * @tc.desc: Test the funcation KeyGestureManager::Dump
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
 * @tc.desc: Test the funcation KeyGestureManager::KeyMonitorIntercept
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
} // namespace MMI
} // namespace OHOS