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
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
int32_t g_no_focus_pid = 1;
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
int32_t g_writeFd = -1;
constexpr size_t MAX_EVENTIDS_SIZE = 1001;
constexpr int32_t REMOVE_OBSERVER { -2 };
constexpr int32_t UNOBSERVED { -1 };
constexpr int32_t ACTIVE_EVENT { 2 };
constexpr int32_t THREE_FINGERS { 3 };
constexpr int32_t FOUR_FINGERS { 4 };
} // namespace

class EventMonitorHandlerTest : public testing::Test {
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
 * @tc.name: EventMonitorHandlerTest_AddInputHandler_002
 * @tc.desc: Verify the invalid and valid event type of AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_AddInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    std::shared_ptr<IInputEventHandler::IInputEventConsumer> callback = std::make_shared<MyInputEventConsumer>();
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback);
    EXPECT_EQ(ret, RET_OK);
    eventType = HANDLE_EVENT_TYPE_NONE;
    ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerTest_AddInputHandler_003
 * @tc.desc: Verify the invalid and valid event type of AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_AddInputHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, session);
    EXPECT_EQ(ret, RET_OK);
    eventType = HANDLE_EVENT_TYPE_FINGERPRINT;
    ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, session);
    EXPECT_EQ(ret, RET_OK);
}

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
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_Key_001
 * @tc.desc: Test Overrides the if (keyEvent->HasFlag(InputEvent::EVENT_FLAG_NO_MONITOR)) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_Key_001, TestSize.Level1)
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
    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_TOUCH_GESTURE;
    monitorCollection.monitors_.insert(sessionHandler);
    for (int i = 0; i < MAX_N_INPUT_MONITORS - 2; i++) {
        SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
        EventMonitorHandler::SessionHandler sessionHandler = { handlerType, eventType, session };
        sessionHandler.eventType_ = HANDLE_EVENT_TYPE_NONE;
        monitorCollection.monitors_.insert(sessionHandler);
    }
    int32_t ret = monitorCollection.AddMonitor(sessionHandler);
    EXPECT_EQ(ret, RET_OK);

    monitorCollection.monitors_.erase(sessionHandler);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler2 { handlerType, eventType, session2 };
    monitorCollection.monitors_.insert(sessionHandler2);
    ret = monitorCollection.AddMonitor(sessionHandler2);
    EXPECT_EQ(ret, RET_OK);

    SessionPtr session3 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler3 { handlerType, eventType, session3 };
    monitorCollection.monitors_.insert(sessionHandler3);
    ret = monitorCollection.AddMonitor(sessionHandler3);
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
    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_TOUCH_GESTURE;
    monitorCollection.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    eventType = 1;
    sessionHandler = { handlerType, eventType, session2 };
    monitorCollection.monitors_.insert(sessionHandler);
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveMonitor_002
 * @tc.desc: Verify the invalid and valid event type of RemoveMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_RemoveMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    monitorCollection.monitors_.insert(sessionHandler);
    std::set<EventMonitorHandler::SessionHandler> setIters = { sessionHandler };
    monitorCollection.endScreenCaptureMonitors_[g_pid] = setIters;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveMonitor(sessionHandler));
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveMonitor_003
 * @tc.desc: Verify the invalid and valid event type of RemoveMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_RemoveMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    monitorCollection.monitors_.insert(sessionHandler);
    std::set<EventMonitorHandler::SessionHandler> setIters = { };
    monitorCollection.endScreenCaptureMonitors_[g_pid] = setIters;
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

/**
 * @tc.name: EventMonitorHandlerTest_ProcessScreenCapture_001
 * @tc.desc: Test ProcessScreenCapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_ProcessScreenCapture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(g_pid, false));
    EventMonitorHandler::MonitorCollection monitorCollection;
    EventMonitorHandler::SessionHandler monitor { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    monitorCollection.monitors_.insert(monitor);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(g_pid, false));
}

/**
 * @tc.name: EventMonitorHandlerTest_ProcessScreenCapture_002
 * @tc.desc: Test ProcessScreenCapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_ProcessScreenCapture_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(g_pid, true));
    EventMonitorHandler::MonitorCollection monitorCollection;
    EventMonitorHandler::SessionHandler monitor { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    monitorCollection.monitors_.insert(monitor);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(g_pid, true));
}

/**
 * @tc.name: EventMonitorHandlerTest_ProcessScreenCapture_003
 * @tc.desc: Test ProcessScreenCapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_ProcessScreenCapture_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::MonitorCollection monitorCollection;
    EventMonitorHandler::SessionHandler handler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    std::set<EventMonitorHandler::SessionHandler> handlerSet;
    handlerSet.insert(handler);
    monitorCollection.endScreenCaptureMonitors_[-1] = handlerSet;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(g_pid, true));
}

/**
 * @tc.name: EventMonitorHandlerTest_Dump_001
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    int32_t fd = 1;
    std::vector<std::string> args;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.Dump(fd, args));
}

/**
 * @tc.name: EventMonitorHandlerTest_OnSessionLost_001
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnSessionLost_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    EventMonitorHandler::MonitorCollection monitorCollection;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY, session };
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    std::set<EventMonitorHandler::SessionHandler> handlerSet;
    handlerSet.insert(sessionHandler);
    monitorCollection.endScreenCaptureMonitors_[-1] = handlerSet;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session));
    eventMonitorHandler.monitors_.monitors_.insert(sessionHandler);
    session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    handlerSet.insert(sessionHandler);
    monitorCollection.endScreenCaptureMonitors_[-1] = handlerSet;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session));
}

/**
 * @tc.name: EventMonitorHandlerTest_RecoveryScreenCaptureMonitor_001
 * @tc.desc: Test RecoveryScreenCaptureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_RecoveryScreenCaptureMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    session->tokenType_ = TokenType::TOKEN_SHELL;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RecoveryScreenCaptureMonitor(session));
    session->tokenType_ = TokenType::TOKEN_HAP;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RecoveryScreenCaptureMonitor(session));
    
    EventMonitorHandler::SessionHandler handler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    std::set<EventMonitorHandler::SessionHandler> handlerSet;
    handlerSet.insert(handler);
    monitorCollection.endScreenCaptureMonitors_[-1] = handlerSet;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RecoveryScreenCaptureMonitor(session));
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveScreenCaptureMonitor_001
 * @tc.desc: Test RemoveScreenCaptureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_RemoveScreenCaptureMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    session->tokenType_ = TokenType::TOKEN_SHELL;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveScreenCaptureMonitor(session));
    session->tokenType_ = TokenType::TOKEN_HAP;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveScreenCaptureMonitor(session));
    EventMonitorHandler::SessionHandler handler { InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_ALL, session };
    std::set<EventMonitorHandler::SessionHandler> handlerSet;
    handlerSet.insert(handler);
    monitorCollection.endScreenCaptureMonitors_[-1] = handlerSet;
    ASSERT_NO_FATAL_FAILURE(monitorCollection.RemoveScreenCaptureMonitor(session));
}

/**
 * @tc.name: EventMonitorHandlerTest_Dump_002
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_Dump_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    int32_t fd = 1;
    std::vector<std::string> args;
    SessionPtr session = nullptr;
    EventMonitorHandler::MonitorCollection monitorCollection;
    EventMonitorHandler::SessionHandler monitor { InputHandlerType::INTERCEPTOR, 2, session };
    monitorCollection.monitors_.insert(monitor);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.Dump(fd, args));
}

/**
 * @tc.name: EventMonitorHandlerTest_Dump_003
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_Dump_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    int32_t fd = 1;
    std::vector<std::string> args;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::MonitorCollection monitorCollection;
    EventMonitorHandler::SessionHandler monitorone { InputHandlerType::INTERCEPTOR, 2, session };
    monitorCollection.monitors_.insert(monitorone);
    EventMonitorHandler::SessionHandler monitortwo { InputHandlerType::MONITOR, 3, session };
    monitorCollection.monitors_.insert(monitortwo);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.Dump(fd, args));
}

/**
 * @tc.name: EventMonitorHandlerTest_CheckHasInputHandler_001
 * @tc.desc: Test CheckHasInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_CheckHasInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    HandleEventType eventType = 1;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.CheckHasInputHandler(eventType));
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::MonitorCollection monitorCollection;
    EventMonitorHandler::SessionHandler monitorone { InputHandlerType::INTERCEPTOR, 1, session };
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.CheckHasInputHandler(eventType));
    monitorCollection.monitors_.insert(monitorone);
    EventMonitorHandler::SessionHandler monitortwo { InputHandlerType::MONITOR, 2, session };
    monitorCollection.monitors_.insert(monitortwo);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.CheckHasInputHandler(eventType));
    EventMonitorHandler::SessionHandler monitorthere { InputHandlerType::MONITOR, 3, session };
    monitorCollection.monitors_.insert(monitorthere);
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.CheckHasInputHandler(eventType));
}

/**
 * @tc.name: EventMonitorHandlerTest_RemoveInputHandler_002
 * @tc.desc: Verify the invalid and valid event type of RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_RemoveInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 2;
    std::shared_ptr<IInputEventHandler::IInputEventConsumer> callback = std::make_shared<MyInputEventConsumer>();
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(handlerType, eventType, callback));
    handlerType = InputHandlerType::NONE;
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(handlerType, eventType, callback));
}

/**
 * @tc.name: EventMonitorHandlerTest_IsPinch
 * @tc.desc: Test IsPinch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsPinch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    bool ret = false;
    ret = monitorCollection.IsPinch(pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ret = monitorCollection.IsPinch(pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = monitorCollection.IsPinch(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsRotate
 * @tc.desc: Test IsRotate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsRotate, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    bool ret = false;
    ret = monitorCollection.IsRotate(pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    ret = monitorCollection.IsRotate(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsThreeFingersSwipe
 * @tc.desc: Test IsThreeFingersSwipe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsThreeFingersSwipe, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    bool ret = false;
    ret = monitorCollection.IsThreeFingersSwipe(pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    ret = monitorCollection.IsThreeFingersSwipe(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsFourFingersSwipe
 * @tc.desc: Test IsFourFingersSwipe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsFourFingersSwipe, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    bool ret = false;
    ret = monitorCollection.IsFourFingersSwipe(pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetFingerCount(FOUR_FINGERS);
    ret = monitorCollection.IsFourFingersSwipe(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsThreeFingersTap
 * @tc.desc: Test IsThreeFingersTap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsThreeFingersTap, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    bool ret = false;
    ret = monitorCollection.IsThreeFingersTap(pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    ret = monitorCollection.IsThreeFingersTap(pointerEvent);
    ASSERT_TRUE(ret);
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
/**
 * @tc.name: EventMonitorHandlerTest_IsFingerprint_001
 * @tc.desc: Test IsFingerprint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsFingerprint_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    bool ret = false;
    ret = monitorCollection.IsFingerprint(pointerEvent);
    ASSERT_FALSE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    ret = monitorCollection.IsFingerprint(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_IsFingerprint_002
 * @tc.desc: Test IsFingerprint_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsFingerprint_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_FALSE(monitorCollection.IsFingerprint(pointerEvent));

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    ASSERT_TRUE(monitorCollection.IsFingerprint(pointerEvent));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_HOLD);
    ASSERT_TRUE(monitorCollection.IsFingerprint(pointerEvent));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_CANCEL);
    ASSERT_TRUE(monitorCollection.IsFingerprint(pointerEvent));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_CANCEL);
    ASSERT_FALSE(monitorCollection.IsFingerprint(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerTest_CheckIfNeedSendFingerprintEvent_001
 * @tc.desc: Test CheckIfNeedSendFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_CheckIfNeedSendFingerprintEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KP;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler monitor { handlerType, eventType, session };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    std::unordered_set<int32_t> fingerFocusPidSet;
    ASSERT_FALSE(monitorCollection.CheckIfNeedSendFingerprintEvent(monitor, pointerEvent, fingerFocusPidSet));
}

/**
 * @tc.name: EventMonitorHandlerTest_CheckIfNeedSendFingerprintEvent_002
 * @tc.desc: Test CheckIfNeedSendFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_CheckIfNeedSendFingerprintEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_FINGERPRINT;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler monitor { handlerType, eventType, session };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK);
    std::unordered_set<int32_t> fingerFocusPidSet;
    ASSERT_TRUE(monitorCollection.CheckIfNeedSendFingerprintEvent(monitor, pointerEvent, fingerFocusPidSet));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    ASSERT_TRUE(monitorCollection.CheckIfNeedSendFingerprintEvent(monitor, pointerEvent, fingerFocusPidSet));

    fingerFocusPidSet.insert(g_pid);
    ASSERT_TRUE(monitorCollection.CheckIfNeedSendFingerprintEvent(monitor, pointerEvent, fingerFocusPidSet));

    fingerFocusPidSet.clear();
    fingerFocusPidSet.insert(g_no_focus_pid);
    ASSERT_FALSE(monitorCollection.CheckIfNeedSendFingerprintEvent(monitor, pointerEvent, fingerFocusPidSet));
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

/**
 * @tc.name: EventMonitorHandlerTest_CheckIfNeedSendToClient_01
 * @tc.desc: Test CheckIfNeedSendToClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_CheckIfNeedSendToClient_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };
    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_FINGERPRINT;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    bool ret = false;
    std::unordered_set<int32_t> fingerFocusPidSet;
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_TOUCH_GESTURE;
    pointerEvent->SetPointerAction(PointerEvent::SOURCE_TYPE_MOUSE);
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_SWIPEINWARD;
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_TOUCH;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_MOUSE;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_PINCH;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_THREEFINGERSSWIP;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: EventMonitorHandlerTest_CheckIfNeedSendToClient_02
 * @tc.desc: Test CheckIfNeedSendToClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_CheckIfNeedSendToClient_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection monitorCollection;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventMonitorHandler::SessionHandler sessionHandler { handlerType, eventType, session };

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_FOURFINGERSSWIP;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    pointerEvent->SetFingerCount(FOUR_FINGERS);
    bool ret = false;
    std::unordered_set<int32_t> fingerFocusPidSet;
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_ROTATE;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_UPDATE);
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);

    sessionHandler.eventType_ = HANDLE_EVENT_TYPE_THREEFINGERSTAP;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    pointerEvent->SetFingerCount(THREE_FINGERS);
    ret = monitorCollection.CheckIfNeedSendToClient(sessionHandler, pointerEvent, fingerFocusPidSet);
    ASSERT_TRUE(ret);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_002
 * @tc.desc: Test OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    InputEventHandler inputEventHandler ;
    inputEventHandler.eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    ASSERT_TRUE(inputEventHandler.eventNormalizeHandler_ != nullptr);
    EventNormalizeHandler eventNormalizeHandler;
    eventNormalizeHandler.currentHandleKeyCode_ = 1;
    keyEvent->SetKeyCode(2);
    bool ret = eventMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    keyEvent->SetKeyCode(1);
    ret = eventMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->bitwise_ = 0x00000002;
    ret = eventMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    inputEvent->bitwise_ = 0x00000000;
    ret = eventMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
    int32_t deviceId = 1;
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    consumptionState.isMonitorConsumed_ = true;
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ret = eventMonitorHandler.OnHandleEvent(keyEvent);
    ASSERT_FALSE(ret);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_X_KEY
/**
 * @tc.name: EventMonitorHandlerTest_IsXKey_001
 * @tc.desc: Test IsXKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_IsXKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler::MonitorCollection eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_X_KEY);
    bool ret = eventMonitorHandler.IsXKey(pointerEvent);
    ASSERT_TRUE(ret);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ret = eventMonitorHandler.IsXKey(pointerEvent);
    ASSERT_FALSE(ret);
}
#endif // OHOS_BUILD_ENABLE_X_KEY

/**
 * @tc.name: EventMonitorHandlerTest_CheckHasInputHandler_002
 * @tc.desc: Test CheckHasInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_CheckHasInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    HandleEventType eventType = 1;
    bool ret = eventMonitorHandler.CheckHasInputHandler(eventType);
    ASSERT_FALSE(ret);
    int32_t deviceId = 1;
    EventMonitorHandler::MonitorCollection::ConsumptionState consumptionState;
    consumptionState.isMonitorConsumed_ = true;
    eventMonitorHandler.monitors_.states_.insert(std::make_pair(deviceId, consumptionState));
    ret = eventMonitorHandler.CheckHasInputHandler(eventType);
    ASSERT_FALSE(ret);
}

#ifdef PLAYER_FRAMEWORK_EXISTS
/**
 * @tc.name: EventMonitorHandlerTest_ProcessScreenCapture_005
 * @tc.desc: Test ProcessScreenCapture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_ProcessScreenCapture_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventMonitorHandler eventMonitorHandler;
    UDSServer udSever;
    InputHandler->udsServer_ = &udSever;
    auto udsServerPtr = InputHandler->GetUDSServer();
    EXPECT_NE(udsServerPtr, nullptr);
    int32_t pid = 2;
    bool isStart = true;
    udSever.idxPidMap_.insert(std::make_pair(pid, 2));
    eventMonitorHandler.ProcessScreenCapture(pid, isStart);
    isStart = false;
    eventMonitorHandler.ProcessScreenCapture(pid, isStart);
}
#endif // PLAYER_FRAMEWORK_EXISTS
} // namespace MMI
} // namespace OHOS
