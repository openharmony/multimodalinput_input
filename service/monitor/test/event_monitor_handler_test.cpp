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

#include <fstream>

#include <gtest/gtest.h>

#include "event_monitor_handler.h"
#include "input_event_data_transformation.h"
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
constexpr size_t MAX_EVENTIDS_SIZE = 1001;
constexpr int32_t REMOVE_OBSERVER { -2 };
constexpr int32_t UNOBSERVED { -1 };
constexpr int32_t ACTIVE_EVENT { 2 };
} // namespace

class EventMonitorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventMonitorHandlerTest_HandlePointerEvent
 * @tc.desc: Test Overrides the if (OnHandleEvent(pointerEvent)) branch of the HandlePointerEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandlePointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t deviceId = 1;
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    pointerEvent->bitwise_ = PointerEvent::EVENT_FLAG_NONE;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetDeviceId(deviceId);
    consumptionState.isMonitorConsumed_ = true;
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_HandleTouchEvent
 * @tc.desc: Test Test Overrides the if (OnHandleEvent(pointerEvent)) branch of the HandleTouchEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandleTouchEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t deviceId = 1;
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    pointerEvent->bitwise_ = PointerEvent::EVENT_FLAG_NONE;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetDeviceId(deviceId);
    consumptionState.isMonitorConsumed_ = true;
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_HandleTouchEvent_001
 * @tc.desc: Test Overrides the if (item.GetToolType() == PointerEvent::TOOL_TYPE_KNUCKLE) branch
 * <br> of the HandleTouchEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandleTouchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->bitwise_ = PointerEvent::EVENT_FLAG_NONE;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_Key
 * @tc.desc: Test Overrides the if (keyEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_Key, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->bitwise_ = InputEvent::EVENT_FLAG_NO_MONITOR;
    ASSERT_FALSE(eventMonitorHandler.OnHandleEvent(keyEvent));
    keyEvent->bitwise_ = InputEvent::EVENT_FLAG_NONE;
    ASSERT_FALSE(eventMonitorHandler.OnHandleEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_Pointer
 * @tc.desc: Test Overrides the if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_Pointer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_NO_MONITOR;
    ASSERT_FALSE(eventMonitorHandler.OnHandleEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_Pointer_001
 * @tc.desc: Test Overrides the if (monitors_.HandleEvent(pointerEvent)) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_Pointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_NONE;
    int32_t deviceId = 1;
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetDeviceId(deviceId);
    consumptionState.isMonitorConsumed_ = true;
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ASSERT_TRUE(eventMonitorHandler.OnHandleEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_MarkConsumed_001
 * @tc.desc: Test Overrides the if (eventIds.find(eventId) != eventIds.cend()) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_MarkConsumed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    int32_t deviceId = 1;
    int32_t eventId = 20;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    consumptionState.eventIds_.insert(20);
    consumptionState.isMonitorConsumed_ = false;
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerTest_MarkConsumed_002
 * @tc.desc: Test Overrides the if (tIter == states_.end()) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_MarkConsumed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    int32_t deviceId = 1;
    int32_t eventId = 20;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    consumptionState.eventIds_.insert(10);
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerTest_MarkConsumed_003
 * @tc.desc: Test Overrides the if (state.isMonitorConsumed_) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_MarkConsumed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    int32_t deviceId = 1;
    int32_t eventId = 10;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    consumptionState.eventIds_.insert(10);
    consumptionState.isMonitorConsumed_ = true;
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerTest_HandleEvent
 * @tc.desc: Test Overrides the if ((mon.eventType_ & HANDLE_EVENT_TYPE_KEY) == HANDLE_EVENT_TYPE_KEY) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandleEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_HandleEvent_001
 * @tc.desc: Test Overwrites the else branch of if ((mon.eventType_ & HANDLE_EVENT_TYPE_KEY) == HANDLE_EVENT_TYPE_KEY)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_NONE, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_HandleEvent_002
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_NONE, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);

    NapProcess::GetInstance()->napClientPid_ = ACTIVE_EVENT;
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = 2;
    napData.uid = 3;
    napData.bundleName = "programName";
    EXPECT_FALSE(NapProcess::GetInstance()->IsNeedNotify(napData));
    bool ret = eventMonitorHandler.monitors_.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_HandleEvent_003
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_NONE, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);

    NapProcess::GetInstance()->napClientPid_ = REMOVE_OBSERVER;
    bool ret = eventMonitorHandler.monitors_.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_HandleEvent_004
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_NONE, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);

    NapProcess::GetInstance()->napClientPid_ = UNOBSERVED;
    bool ret = eventMonitorHandler.monitors_.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_Monitor
 * @tc.desc: Test Monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_Monitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetButtonId(1);
    pointerEvent->SetFingerCount(2);
    pointerEvent->SetZOrder(100);
    pointerEvent->SetDispatchTimes(1000);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetHandlerEventType(HANDLE_EVENT_TYPE_POINTER);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sess { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_POINTER, session };
    eventMonitorHandler.monitors_.monitors_.insert(sess);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.Monitor(pointerEvent));

    pointerEvent->SetHandlerEventType(HANDLE_EVENT_TYPE_FINGERPRINT);
    EventMonitorHandler::SessionHandler sesshdl { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_NONE, session };
    eventMonitorHandler.monitors_.monitors_.insert(sesshdl);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.Monitor(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_Monitor_01
 * @tc.desc: Test Monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_Monitor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetButtonId(1);
    pointerEvent->SetFingerCount(2);
    pointerEvent->SetZOrder(100);
    pointerEvent->SetDispatchTimes(1000);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetHandlerEventType(HANDLE_EVENT_TYPE_FINGERPRINT);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sess { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_NONE, session };
    eventMonitorHandler.monitors_.monitors_.insert(sess);

    NapProcess::GetInstance()->napClientPid_ = ACTIVE_EVENT;
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = 2;
    napData.uid = 3;
    napData.bundleName = "programName";
    EXPECT_FALSE(NapProcess::GetInstance()->IsNeedNotify(napData));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.Monitor(pointerEvent));

    NapProcess::GetInstance()->napClientPid_ = REMOVE_OBSERVER;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.Monitor(pointerEvent));

    NapProcess::GetInstance()->napClientPid_ = UNOBSERVED;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.monitors_.Monitor(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_001
 * @tc.desc: Test OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
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
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
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
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
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
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    NetPacket keyEventPkt(MmiMessageId::REPORT_KEY_EVENT);
    keyEventPkt << InputHandlerType::MONITOR << static_cast<uint32_t>(evdev_device_udev_tags::EVDEV_UDEV_TAG_INPUT);
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(keyEvent, keyEventPkt));

    NetPacket pointerEventPkt(MmiMessageId::REPORT_POINTER_EVENT);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEventPkt << InputHandlerType::MONITOR << static_cast<uint32_t>(evdev_device_udev_tags::EVDEV_UDEV_TAG_INPUT);
    InputEventDataTransformation::Marshalling(pointerEvent, pointerEventPkt);
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(pointerEvent, pointerEventPkt));
}

/**
 * @tc.name: EventMonitorHandlerTest_AddMonitor_001
 * @tc.desc: Verify the invalid and valid event type of AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_AddMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    for (int32_t i = 0; i < MAX_N_INPUT_MONITORS - 1; i++) {
        SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
        EventMonitorHandler::SessionHandler sessionHandler = { handlerType, eventType, session };
        monitorCollection.monitors_.insert(sessionHandler);
    }
    int32_t ret = monitorCollection.AddMonitor(sessionHandler);
    EXPECT_EQ(ret, RET_OK);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
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
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
    monitorCollection.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    eventType = 1;
    sessionHandler = { handlerType, eventType, session2 };
    monitorCollection.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
}

/**
 * @tc.name: EventMonitorHandlerTest_MarkConsumed
 * @tc.desc: Test MarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_MarkConsumed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    int32_t eventId = 100;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerTest_OnSessionLost
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnSessionLost, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session));

    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session));
}

/**
 * @tc.name: EventMonitorHandlerTest_HasMonitor
 * @tc.desc: Test HasMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_HasMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler monitor { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    monitorCollection.monitors_.insert(monitor);
    ASSERT_TRUE(monitorCollection.HasMonitor(session));
}

/**
 * @tc.name: EventMonitorHandlerTest_UpdateConsumptionState
 * @tc.desc: Test UpdateConsumptionState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_UpdateConsumptionState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetDeviceId(deviceId);
    EventMonitorHandler::MonitorCollection::ConsumptionState state;
    for (int32_t i = 0; i <= MAX_EVENTIDS_SIZE; ++i) {
        state.eventIds_.insert(i);
    }
    monitorCollection.states_.insert(std::make_pair(deviceId, state));
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.UpdateConsumptionState(pointerEvent));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.UpdateConsumptionState(pointerEvent));
}
} // namespace MMI
} // namespace OHOS
