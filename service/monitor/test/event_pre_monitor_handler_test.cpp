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

#include <fstream>

#include <gtest/gtest.h>

#include "event_pre_monitor_handler.h"
#include "input_event_handler.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT { 0 };
static constexpr char PROGRAM_NAME[] = "uds_sesion_test";
int32_t g_moduleType = 3;
int32_t g_pid = 0;
int32_t g_writeFd = -1;
} // namespace

class EventPreMonitorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MyInputEventConsumer : public IInputEventHandler::IInputEventConsumer {
public:
    void OnInputEvent(InputHandlerType type, std::shared_ptr<KeyEvent> event) const override {}
    void OnInputEvent(InputHandlerType type, std::shared_ptr<PointerEvent> event) const override {}
    void OnInputEvent(InputHandlerType type, std::shared_ptr<AxisEvent> event) const override {}
};

/**
 * @tc.name: EventPreMonitorHandlerTest_HandleKeyEvent_001
 * @tc.desc: Test Overrides the if (HandleKeyEvent(keyEvent)) branch of the HandleKeyEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_HandleKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(eventPreMonitorHandler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_HandlePointerEvent_001
 * @tc.desc: Test Overrides the if (HandlePointerEvent(pointerEvent)) branch of the HandlePointerEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_HandlePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(eventPreMonitorHandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_HandleTouchEvent_001
 * @tc.desc: Test Overrides the if (HandleTouchEvent(pointerEvent)) branch of the HandleTouchEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_HandleTouchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(eventPreMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_OnHandleEvent_001
 * @tc.desc: Test Overrides the if (OnHandleEvent(keyEvent)) branch of the OnHandleEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_OnHandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    bool ret = eventPreMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    keyEvent->bitwise_ = InputEvent::EVENT_FLAG_NO_MONITOR;
    ASSERT_FALSE(eventPreMonitorHandler.OnHandleEvent(keyEvent));
    keyEvent->bitwise_ = InputEvent::EVENT_FLAG_NONE;
    ASSERT_FALSE(eventPreMonitorHandler.OnHandleEvent(keyEvent));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_InitSessionLostCallback_001
 * @tc.desc: Verify the invalid and valid event type of InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_InitSessionLostCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    eventPreMonitorHandler.sessionLostCallbackInitialized_ = true;
    eventPreMonitorHandler.InitSessionLostCallback();
    eventPreMonitorHandler.sessionLostCallbackInitialized_ = false;
    UDSServer udSever;
    InputHandler->udsServer_ = &udSever;
    auto udsServerPtr = InputHandler->GetUDSServer();
    EXPECT_NE(udsServerPtr, nullptr);
    eventPreMonitorHandler.InitSessionLostCallback();
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: EventPreMonitorHandlerTest_AddInputHandler_001
 * @tc.desc: Verify the invalid and valid event type of AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_AddInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SessionPtr sess;
    EventPreMonitorHandler eventPreMonitorHandler;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    std::vector<int32_t> keys = {1, 2, 3};
    int32_t ret = eventPreMonitorHandler.AddInputHandler(sess, 1, eventType, keys);
    EXPECT_EQ(ret, RET_ERR);
    eventType = HANDLE_EVENT_TYPE_NONE;
    ret = eventPreMonitorHandler.AddInputHandler(sess, 1, eventType, keys);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: EventPreMonitorHandlerTest_RemoveInputHandler_001
 * @tc.desc: Verify the invalid and valid event type of RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_RemoveInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    SessionPtr sess;
    ASSERT_NO_FATAL_FAILURE(eventPreMonitorHandler.RemoveInputHandler(sess, 1));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_OnSessionLost
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_OnSessionLost, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    std::vector<int32_t> keys = {1, 2, 3};
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    eventPreMonitorHandler.monitors_.sessionHandlers_[keys] =
        std::list<std::shared_ptr<EventPreMonitorHandler::SessionHandler>>();
    eventPreMonitorHandler.monitors_.sessionHandlers_[keys].push_back(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(eventPreMonitorHandler.OnSessionLost(session));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_OnSessionLost_001
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_OnSessionLost_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(eventPreMonitorHandler.OnSessionLost(session));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_AddMonitor_001
 * @tc.desc: Verify the invalid and valid event type of AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_AddMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    std::vector<int32_t> keys = {1, 2, 3};
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    monitorCollection.sessionHandlers_[keys] = std::list<std::shared_ptr<EventPreMonitorHandler::SessionHandler>>();
    monitorCollection.sessionHandlers_[keys].push_back(sessionHandler);
    for (int i = 0; i < MAX_N_INPUT_MONITORS - 2; i++) {
        SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
        auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
        monitorCollection.sessionHandlers_[keys].push_back(sessionHandler);
    }
    int32_t ret = monitorCollection.AddMonitor(sessionHandler, keys);
    EXPECT_EQ(ret, RET_OK);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    auto sessionHandler2 = std::make_shared<EventPreMonitorHandler::SessionHandler>(session2, 1, eventType, keys);
    monitorCollection.sessionHandlers_[keys].push_back(sessionHandler2);
    ret = monitorCollection.AddMonitor(sessionHandler2, keys);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventPreMonitorHandlerTest_RemoveMonitor_001
 * @tc.desc: Verify the invalid and valid event type of RemoveMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_RemoveMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    std::vector<int32_t> keys = {1, 2, 3};
    monitorCollection.sessionHandlers_[keys] = std::list<std::shared_ptr<EventPreMonitorHandler::SessionHandler>>();
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(session, 1));
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(session, 2));
    monitorCollection.sessionHandlers_[keys].push_back(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(session, 1));
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(session, 2));
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    eventType = 1;
    sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session2, 1, eventType, keys);
    monitorCollection.sessionHandlers_[keys].push_back(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(session2, 1));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_IsEqualsKeys_001
 * @tc.desc: Verify the invalid and valid event type of IsEqualsKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_IsEqualsKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    std::vector<int32_t> newKeys;
    std::vector<int32_t> oldKeys = {1, 2, 3};
    ASSERT_FALSE(monitorCollection.IsEqualsKeys(newKeys, oldKeys));
    newKeys = {1, 2, 3};
    ASSERT_TRUE(monitorCollection.IsEqualsKeys(newKeys, oldKeys));
    oldKeys = {1, 2, 3, 4};
    ASSERT_FALSE(monitorCollection.IsEqualsKeys(newKeys, oldKeys));
    oldKeys = {1, 2, 3};
    newKeys = {1, 2, 3, 4};
    ASSERT_FALSE(monitorCollection.IsEqualsKeys(newKeys, oldKeys));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_SendToClient_001
 * @tc.desc: Verify the keyEvent and pointerEvent of SendToClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_SendToClient_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    std::vector<int32_t> keys = {1, 2, 3};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    NetPacket keyEventPkt(MmiMessageId::ON_PRE_KEY_EVENT);
    ASSERT_NO_FATAL_FAILURE(sessionHandler->SendToClient(keyEvent, keyEventPkt, 1));
}
} // namespace MMI
} // namespace OHOS
