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
    EXPECT_EQ(ret, -1);
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

/**
 * @tc.name: EventPreMonitorHandlerTest_AddInputHandler_002
 * @tc.desc: Verify the invalid and valid event type of AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_AddInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SessionPtr sess;
    EventPreMonitorHandler eventPreMonitorHandler;
    HandleEventType eventType = HANDLE_EVENT_TYPE_ALL;
    std::vector<int32_t> keys = {1, 2, 3};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NE(session, nullptr);
    int32_t ret = eventPreMonitorHandler.AddInputHandler(sess, 1, eventType, keys);
    EXPECT_EQ(ret, RET_ERR);
    eventType = HANDLE_EVENT_TYPE_NONE;
    ret = eventPreMonitorHandler.AddInputHandler(sess, 1, eventType, keys);
    EXPECT_EQ(ret, RET_ERR);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: EventPreMonitorHandlerTest_OnHandleEvent_002
 * @tc.desc: Test OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_OnHandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler eventPreMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    InputEventHandler inputEventHandler ;
    inputEventHandler.eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    ASSERT_NE(inputEventHandler.eventNormalizeHandler_, nullptr);
    keyEvent->SetKeyCode(1);
    EventNormalizeHandler eventNormalizeHandler;
    eventNormalizeHandler.currentHandleKeyCode_ = 2;
    bool ret = eventPreMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    eventNormalizeHandler.currentHandleKeyCode_ = 1;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->bitwise_ = 0x00000002;
    ret = eventPreMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    inputEvent->bitwise_ = 0x00000000;
    ret = eventPreMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
 * @tc.name: EventPreMonitorHandlerTest_SendToClient_002
 * @tc.desc: Verify the keyEvent and pointerEvent of SendToClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_SendToClient_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    std::vector<int32_t> keys = {1, 2, 3};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    NetPacket keyEventPkt(MmiMessageId::ON_PRE_KEY_EVENT);
    std::vector<KeyEvent::KeyItem> keyItems;
    for (int i = 0; i < 400; ++i) {
        KeyEvent::KeyItem item;
        item.deviceId_ = i;
        item.keyCode_ = i;
        item.downTime_ = i;
        keyItems.push_back(item);
    }
    keyEvent->SetKeyItem(keyItems);
    ASSERT_NO_FATAL_FAILURE(sessionHandler->SendToClient(keyEvent, keyEventPkt, 1));
}

/**
 * @tc.name: EventPreMonitorHandlerTest_AddMonitor_001
 * @tc.desc: Verify the invalid and valid event type of AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_AddMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    std::vector<int32_t> keys = {1, 2, 3};
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    for (int i = 0; i < 20; ++i) {
        std::vector<int32_t> key = {i};
        std::list<std::shared_ptr<EventPreMonitorHandler::SessionHandler>> value;
        value.push_back(std::make_shared<EventPreMonitorHandler::SessionHandler>(session, i, eventType, keys));
        monitorCollection.sessionHandlers_[key] = value;
    }
    int32_t ret = monitorCollection.AddMonitor(sessionHandler, keys);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: EventPreMonitorHandlerTest_AddMonitor_001
 * @tc.desc: Verify the invalid and valid event type of AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_AddMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    std::vector<int32_t> keys = {1, 2, 3};
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    for (int i = 0; i < 15; ++i) {
        std::vector<int32_t> key = {i};
        std::list<std::shared_ptr<EventPreMonitorHandler::SessionHandler>> value;
        value.push_back(std::make_shared<EventPreMonitorHandler::SessionHandler>(session, i, eventType, keys));
        monitorCollection.sessionHandlers_[key] = value;
    }
    int32_t ret = monitorCollection.AddMonitor(sessionHandler, keys);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventPreMonitorHandlerTest_IsEqualsKeys_002
 * @tc.desc: Verify the invalid and valid event type of IsEqualsKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_IsEqualsKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    std::vector<int32_t> newKeys = {1, 2, 3};
    std::vector<int32_t> oldKeys = {4, 5, 6};
    bool ret = monitorCollection.IsEqualsKeys(newKeys, oldKeys);
    ASSERT_FALSE(ret);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: EventPreMonitorHandlerTest_HandleEvent_001
 * @tc.desc: Verify HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    EventPreMonitorHandler eventPreMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    StreamBuffer streamBuffer;
    streamBuffer.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    bool ret = monitorCollection.HandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    streamBuffer.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    ret = monitorCollection.HandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    std::vector<int32_t> keys = {1, 2, 3};
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    eventPreMonitorHandler.monitors_.sessionHandlers_[keys] =
        std::list<std::shared_ptr<EventPreMonitorHandler::SessionHandler>>();
    eventPreMonitorHandler.monitors_.sessionHandlers_[keys].push_back(sessionHandler);
    sessionHandler->keys_ = {1, 2, 3};
    keyEvent->SetKeyCode(2);
    ret = monitorCollection.HandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    keyEvent->SetKeyCode(5);
    ret = monitorCollection.HandleEvent(keyEvent);
    ASSERT_FALSE(ret);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

/**
 * @tc.name: EventPreMonitorHandlerTest_Dump_001
 * @tc.desc: Verify the invalid and valid event type of Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventPreMonitorHandlerTest, EventPreMonitorHandlerTest_Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventPreMonitorHandler::MonitorCollection monitorCollection;
    int32_t fd = 1;
    std::vector<std::string> args;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.Dump(fd, args));
    EventPreMonitorHandler eventPreMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    std::vector<int32_t> keys = {1, 2, 3};
    auto sessionHandler = std::make_shared<EventPreMonitorHandler::SessionHandler>(session, 1, eventType, keys);
    eventPreMonitorHandler.monitors_.sessionHandlers_[keys] =
        std::list<std::shared_ptr<EventPreMonitorHandler::SessionHandler>>();
    eventPreMonitorHandler.monitors_.sessionHandlers_[keys].push_back(sessionHandler);
    ret = eventPreMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
