/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <fstream>

#define private public
#include "event_monitor_handler.h"
#include "input_event_handler.h"
#undef private
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT { 0 };
static constexpr char PROGRAM_NAME[] = "uds_sesion_test";
int32_t moduleType_ = 3;
static inline int32_t pid_ = 0;
int32_t writeFd_ = -1;
} // namespace

class EventMonitorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_001
 * @tc.desc: Test OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    eventMonitorHandler.HandleKeyEvent(keyEvent);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(keyEvent), false);
    auto pointerEvent = PointerEvent::Create();
    eventMonitorHandler.HandlePointerEvent(pointerEvent);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(pointerEvent), false);

    eventMonitorHandler.HandleTouchEvent(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    item.SetPointerId(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    item.SetDisplayY(610);
    item.SetPointerId(1);
    item.SetDeviceId(1);
    item.SetPressure(7);
    item.SetDisplayX(600);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEvent->SetActionTime(100);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->ActionToString(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->KeyCodeToString(KeyEvent::KEYCODE_BACK);
    KeyEvent::KeyItem part;
    part.SetKeyCode(KeyEvent::KEYCODE_BACK);
    part.SetDownTime(100);
    part.SetPressed(true);
    part.SetUnicode(0);
    keyEvent->AddKeyItem(part);

    eventMonitorHandler.HandlePointerEvent(pointerEvent);
    eventMonitorHandler.HandleTouchEvent(pointerEvent);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(keyEvent), false);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(pointerEvent), false);
}

/**
 * @tc.name: EventMonitorHandlerTest_InitSessionLostCallback_001
 * @tc.desc: Verify the invalid and valid event type of InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_InitSessionLostCallback_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    eventMonitorHandler.sessionLostCallbackInitialized_ = true;
    eventMonitorHandler.InitSessionLostCallback();
    eventMonitorHandler.sessionLostCallbackInitialized_ = false;
    UDSServer udSever;
    InputHandler->udsServer_ = &udSever;
    auto udsServerPtr = InputHandler->GetUDSServer();
    EXPECT_NE(udsServerPtr, nullptr);
    eventMonitorHandler.InitSessionLostCallback();
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: EventMonitorHandlerTest_AddInputHandler_001
 * @tc.desc: Verify the invalid and valid event type of AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_AddInputHandler_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, session);
    EXPECT_EQ(ret, RET_ERR);
    eventType = 1;
    ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, session);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveInputHandler_001
 * @tc.desc: Verify the invalid and valid event type of RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_RemoveInputHandler_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(handlerType, eventType, session));
    handlerType = InputHandlerType::MONITOR;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(handlerType, eventType, session));
}

/**
 * @tc.name: EventMonitorHandlerTest_SendToClient_001
 * @tc.desc: Verify the keyEvent and pointerEvent of SendToClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_SendToClient_001, TestSize.Level1)
{
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(keyEvent));
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_AddMonitor_001
 * @tc.desc: Verify the invalid and valid event type of AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_AddMonitor_001, TestSize.Level1)
{
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    for (int i = 0; i < MAX_N_INPUT_MONITORS - 1; i++) {
        SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
        EventMonitorHandler::SessionHandler sessionHandler = { handlerType, eventType, session };
        monitorCollection.monitors_.insert(sessionHandler);
    }
    int32_t ret = monitorCollection.AddMonitor(sessionHandler);
    EXPECT_EQ(ret, RET_OK);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    EventMonitorHandler::SessionHandler sessionHandler2 { handlerType, eventType, session2 };
    monitorCollection.monitors_.insert(sessionHandler2);
    ret = monitorCollection.AddMonitor(sessionHandler2);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveMonitor_001
 * @tc.desc: Verify the invalid and valid event type of RemoveMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_RemoveMonitor_001, TestSize.Level1)
{
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
    monitorCollection.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, moduleType_, writeFd_, UID_ROOT, pid_);
    eventType = 1;
    sessionHandler = { handlerType, eventType, session2 };
    monitorCollection.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
}
} // namespace MMI
} // namespace OHOS
