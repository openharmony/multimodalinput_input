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
#include "input_active_subscriber_handler.h"
#include "key_gesture_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputActiveSubscriberHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputActiveSubscriberHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputActiveSubscriberHandlerTest_SubscribeInputActive_001
 * @tc.desc: Verify SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_SubscribeInputActive_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    auto ret = handler.SubscribeInputActive(session, -1, 500);
    EXPECT_NE(ret, RET_OK);
    int32_t subscribeId = 0;
    ret = handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(ret, RET_OK);
    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
    subscribeId = 1;
    ret = handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(ret, RET_OK);
    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_UnsubscribeInputActive_001
 * @tc.desc: Verify UnsubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_UnsubscribeInputActive_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    auto ret = handler.SubscribeInputActive(session, -1, 500);
    EXPECT_NE(ret, RET_OK);
    int32_t subscribeId = 1;
    ret = handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(ret, RET_OK);
    subscribeId = 2;
    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_OnSubscribeInputActive_001
 * @tc.desc: Verify OnSubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_OnSubscribeInputActive_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.HandleKeyEvent(keyEvent);
#ifdef OHOS_BUILD_ENABLE_SWITCH
    handler.HandleSwitchEvent(nullptr);
#endif
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    int32_t subscribeId = 0;
    auto ret = handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(ret, RET_OK);
    handler.subscribers_.push_back(nullptr);
    handler.OnSubscribeInputActive(keyEvent);
    handler.OnSubscribeInputActive(keyEvent);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_OnSubscribeInputActive_002
 * @tc.desc: Verify OnSubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_OnSubscribeInputActive_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    ASSERT_NE(pointerEvent, nullptr);
    handler.HandlePointerEvent(pointerEvent);
    handler.HandleTouchEvent(pointerEvent);
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    int32_t subscribeId = 0;
    auto ret = handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(ret, RET_OK);
    handler.subscribers_.push_back(nullptr);
    handler.OnSubscribeInputActive(pointerEvent);
    handler.OnSubscribeInputActive(pointerEvent);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_IsImmediateNotifySubscriber_001
 * @tc.desc: Verify IsImmediateNotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest,
    InputActiveSubscriberHandlerTest_IsImmediateNotifySubscriber_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    std::shared_ptr<InputActiveSubscriberHandler::Subscriber> subscriber =
        std::make_shared<InputActiveSubscriberHandler::Subscriber>(0, session, 0);
    ASSERT_NE(subscriber, nullptr);
    int64_t currentTime = 0;
    bool result = handler.IsImmediateNotifySubscriber(subscriber, currentTime);
    EXPECT_EQ(result, true);
    subscriber->sendEventLastTime_ = 0;
    subscriber->interval_ = 500;
    result = handler.IsImmediateNotifySubscriber(subscriber, currentTime);
    EXPECT_EQ(result, true);
    currentTime = 300;
    subscriber->sendEventLastTime_ = 500;
    result = handler.IsImmediateNotifySubscriber(subscriber, currentTime);
    EXPECT_EQ(result, true);
    EXPECT_EQ(subscriber->sendEventLastTime_, 0);
    currentTime = 1200;
    subscriber->sendEventLastTime_ = 500;
    result = handler.IsImmediateNotifySubscriber(subscriber, currentTime);
    EXPECT_EQ(result, true);
    currentTime = 800;
    subscriber->sendEventLastTime_ = 500;
    result = handler.IsImmediateNotifySubscriber(subscriber, currentTime);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_InsertSubscriber_001
 * @tc.desc: Verify InsertSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_InsertSubscriber_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    std::shared_ptr<InputActiveSubscriberHandler::Subscriber> subscriber =
        std::make_shared<InputActiveSubscriberHandler::Subscriber>(0, session, 0);
    ASSERT_NE(subscriber, nullptr);
    handler.InsertSubscriber(subscriber);
    handler.InsertSubscriber(subscriber);
    session = std::make_shared<UDSSession>("test_program1", 2, 124, 3000, 4000);
    ASSERT_NE(session, nullptr);
    subscriber = std::make_shared<InputActiveSubscriberHandler::Subscriber>(1, session, 0);
    ASSERT_NE(subscriber, nullptr);
    handler.InsertSubscriber(subscriber);
    subscriber = std::make_shared<InputActiveSubscriberHandler::Subscriber>(1, nullptr, 0);
    ASSERT_NE(subscriber, nullptr);
    handler.InsertSubscriber(subscriber);
    std::vector<std::string> args;
    handler.Dump(1, args);
    handler.OnSessionDelete(session);
    handler.callbackInitialized_ = true;
    handler.InitSessionDeleteCallback();
    handler.callbackInitialized_ = false;
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_StartIntervalTimer_001
 * @tc.desc: Verify StartIntervalTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_StartIntervalTimer_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    ASSERT_NE(pointerEvent, nullptr);
    handler.HandlePointerEvent(pointerEvent);
    handler.HandleTouchEvent(pointerEvent);
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    std::shared_ptr<InputActiveSubscriberHandler::Subscriber> subscriber =
        std::make_shared<InputActiveSubscriberHandler::Subscriber>(0, session, 500);
    ASSERT_NE(subscriber, nullptr);
    subscriber->sendEventLastTime_ = 401;
    subscriber->lastEventType_ = InputActiveSubscriberHandler::EVENTTYPE_POINTER;
    subscriber->pointerEvent_ = pointerEvent;
    int64_t currTime = 880;
    handler.StartIntervalTimer(subscriber, currTime);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    subscriber->lastEventType_ = InputActiveSubscriberHandler::EVENTTYPE_KEY;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    subscriber->keyEvent_ = keyEvent;
    handler.StartIntervalTimer(subscriber, currTime);
    handler.CleanSubscribeInfo(subscriber, currTime);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_NotifySubscriber_001
 * @tc.desc: Verify NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_NotifySubscriber_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    std::shared_ptr<InputActiveSubscriberHandler::Subscriber> subscriber =
        std::make_shared<InputActiveSubscriberHandler::Subscriber>(0, nullptr, 0);
    ASSERT_NE(subscriber, nullptr);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.NotifySubscriber(keyEvent, subscriber);
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    ASSERT_NE(pointerEvent, nullptr);
    handler.NotifySubscriber(pointerEvent, subscriber);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_SubscribeInputActive_002
 * @tc.desc: Verify SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_SubscribeInputActive_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, 123, 1000, 2000);
    auto session3 = std::make_shared<UDSSession>("test_program3", 1, 123, 1000, 2000);
    auto session4 = std::make_shared<UDSSession>("test_program4", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(session2, nullptr);
    ASSERT_NE(session3, nullptr);
    ASSERT_NE(session4, nullptr);
    auto ret = handler.SubscribeInputActive(session, -1, 500);
    EXPECT_NE(ret, RET_OK);
    int32_t subscribeId = 0;
    ret = handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(ret, RET_OK);
    handler.SubscribeInputActive(session, subscribeId, 500);
    handler.SubscribeInputActive(session, subscribeId + 1, 500);
    handler.SubscribeInputActive(session2, subscribeId, 500);
    handler.SubscribeInputActive(session2, subscribeId + 1, 500);
    handler.SubscribeInputActive(session2, subscribeId + 2, -1);
    handler.SubscribeInputActive(nullptr, subscribeId, 500);
    handler.subscribers_.push_back(nullptr);
    handler.SubscribeInputActive(session4, subscribeId, 500);
    handler.subscribers_.back()->sess_ = nullptr;
    std::vector<std::string> args;
    handler.Dump(1, args);

    int32_t size = handler.subscribers_.size();
    EXPECT_NE(size, 0);
    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(handler.subscribers_.size(), size - 1);
    ret = handler.UnsubscribeInputActive(session3, subscribeId);
    EXPECT_EQ(handler.subscribers_.size(), size - 1);
    ret = handler.UnsubscribeInputActive(session, subscribeId + 1);
    EXPECT_EQ(handler.subscribers_.size(), size - 2);
    ret = handler.UnsubscribeInputActive(session2, subscribeId);
    EXPECT_EQ(handler.subscribers_.size(), size - 3);
    ret = handler.UnsubscribeInputActive(session2, subscribeId + 1);
    EXPECT_EQ(handler.subscribers_.size(), size - 4);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.HandleKeyEvent(keyEvent);
    handler.SubscribeInputActive(session, subscribeId, -1);
    handler.subscribers_.push_back(nullptr);
    EXPECT_NO_FATAL_FAILURE(handler.OnSubscribeInputActive(keyEvent));
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    ASSERT_NE(pointerEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(handler.OnSubscribeInputActive(pointerEvent));
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_OnSessionDelete_001
 * @tc.desc: Verify OnSessionDelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_OnSessionDelete_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, 123, 1000, 2000);
    ASSERT_NE(session, nullptr);
    ASSERT_NE(session2, nullptr);
    int32_t subscribeId = 0;
    handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(handler.subscribers_.size(), 1);
    handler.OnSessionDelete(session);
    EXPECT_EQ(handler.subscribers_.size(), 0);
    handler.SubscribeInputActive(session, subscribeId, 500);
    handler.subscribers_.push_back(nullptr);
    EXPECT_EQ(handler.subscribers_.size(), 2);
    handler.OnSessionDelete(session2);
    EXPECT_EQ(handler.subscribers_.size(), 2);
    handler.callbackInitialized_ = true;
    auto ret = handler.InitSessionDeleteCallback();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest
 * @tc.desc: Test the function ResetTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, KeyGestureManagerTest_ResetTimer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::Handler handler(1, 2, 3000, nullptr);
    handler.timerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(handler.ResetTimer());
    handler.timerId_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler.ResetTimer());
}

/**
 * @tc.name: KeyGestureManagerTest_Trigger
 * @tc.desc: Test the function Trigger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, KeyGestureManagerTest_Trigger, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::Handler handler(1, 2, 3000, nullptr);
    handler.timerId_ = -1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.Trigger(keyEvent));
    handler.timerId_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler.Trigger(keyEvent));
}

/**
 * @tc.name: KeyGestureManagerTest_Run
 * @tc.desc: Test the function Run
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, KeyGestureManagerTest_Run, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyGestureManager::Handler handler(1, 2, 3000, nullptr);
    handler.keyEvent_ = nullptr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.Run(keyEvent));
    ASSERT_NO_FATAL_FAILURE(handler.RunPending());
    std::function<void(std::shared_ptr<KeyEvent>)> myCallback;
    handler.callback_ = myCallback;
    handler.keyEvent_ = keyEvent;
    ASSERT_NO_FATAL_FAILURE(handler.Run(keyEvent));
    ASSERT_NO_FATAL_FAILURE(handler.RunPending());
}
} // namespace MMI
} // namespace OHOS