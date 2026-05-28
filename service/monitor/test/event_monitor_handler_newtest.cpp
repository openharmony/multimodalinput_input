/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <string>
#include <vector>

#include "event_monitor_handler.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT { 0 };
static constexpr char PROGRAM_NAME[] = "uds_session_test";
int32_t g_moduleType = 3;
int32_t g_pid = 0;
int32_t g_writeFd = -1;
} // namespace

class MockInputEventConsumer : public IInputEventHandler::IInputEventConsumer {
public:
    MOCK_METHOD(void, OnInputEvent, (InputHandlerType type, std::shared_ptr<KeyEvent> event), (const, override));
    MOCK_METHOD(void, OnInputEvent, (InputHandlerType type, std::shared_ptr<PointerEvent> event), (const, override));
    MOCK_METHOD(void, OnInputEvent, (InputHandlerType type, std::shared_ptr<AxisEvent> event), (const, override));
};

class EventMonitorHandlerNewTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_001
 * @tc.desc: Test AddInputHandler with key event and callback
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Key_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_002
 * @tc.desc: Test AddInputHandler with invalid event type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Key_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_003
 * @tc.desc: Test AddInputHandler with key event and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Key_003, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, session, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_004
 * @tc.desc: Test AddInputHandler with key event and invalid session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Key_004, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    SessionPtr session = nullptr;
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, session, gestureType, fingers);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Pointer_001
 * @tc.desc: Test AddInputHandler with pointer event and callback
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Pointer_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_POINTER;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Pointer_002
 * @tc.desc: Test AddInputHandler with pointer event and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Pointer_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_POINTER;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, session, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Touch_001
 * @tc.desc: Test AddInputHandler with touch event and callback
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Touch_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_TOUCH;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Actions_001
 * @tc.desc: Test AddInputHandler with actions vector and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Actions_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    std::vector<int32_t> actionsType = {PointerEvent::POINTER_ACTION_DOWN, PointerEvent::POINTER_ACTION_UP};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, actionsType, session);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Actions_002
 * @tc.desc: Test AddInputHandler with actions vector and invalid session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Actions_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    std::vector<int32_t> actionsType = {PointerEvent::POINTER_ACTION_DOWN, PointerEvent::POINTER_ACTION_UP};
    SessionPtr session = nullptr;
    
    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, actionsType, session);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_Key_001
 * @tc.desc: Test RemoveInputHandler with key event and callback
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_Key_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    // First add a handler
    eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    // Then remove it - should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(
        handlerType, eventType, callback, gestureType, fingers));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_Key_002
 * @tc.desc: Test RemoveInputHandler with key event and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_Key_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;
    
    // First add a handler
    eventMonitorHandler.AddInputHandler(handlerType, eventType, session, gestureType, fingers);
    // Then remove it - should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(
        handlerType, eventType, session, gestureType, fingers));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_Actions_001
 * @tc.desc: Test RemoveInputHandler with actions vector and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_Actions_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    std::vector<int32_t> actionsType = {PointerEvent::POINTER_ACTION_DOWN, PointerEvent::POINTER_ACTION_UP};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    
    // First add a handler
    eventMonitorHandler.AddInputHandler(handlerType, actionsType, session);
    // Then remove it - should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(handlerType, actionsType, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_MarkConsumed_001
 * @tc.desc: Test MarkConsumed with valid event and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_MarkConsumed_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t eventId = 100;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    
    // First add a handler for this session
    auto callback = std::make_shared<MockInputEventConsumer>();
    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, session, TOUCH_GESTURE_TYPE_NONE, 0);
    
    // Mark consumed - should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_MarkConsumed_002
 * @tc.desc: Test MarkConsumed with invalid session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_MarkConsumed_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t eventId = 100;
    SessionPtr session = nullptr;
    
    // Mark consumed with null session - should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_CheckHasInputHandler_001
 * @tc.desc: Test CheckHasInputHandler with no handlers
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_CheckHasInputHandler_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    
    bool result = eventMonitorHandler.CheckHasInputHandler(eventType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_CheckHasInputHandler_002
 * @tc.desc: Test CheckHasInputHandler with registered handler
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_CheckHasInputHandler_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    auto callback = std::make_shared<MockInputEventConsumer>();
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    
    // Add a handler
    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, eventType, session, TOUCH_GESTURE_TYPE_NONE, 0);
    
    bool result = eventMonitorHandler.CheckHasInputHandler(eventType);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_Dump_001
 * @tc.desc: Test Dump function
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_Dump_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t fd = 1; // stdout
    std::vector<std::string> args;
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.Dump(fd, args));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_GetMonitorCollection_001
 * @tc.desc: Test GetMonitorCollection function
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_GetMonitorCollection_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    
    const ISessionHandlerCollection* collection = eventMonitorHandler.GetMonitorCollection();
    EXPECT_NE(collection, nullptr);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Key_001
 * @tc.desc: Test OnHandleEvent with key event having no monitor flag
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Key_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_MONITOR);
    
    bool result = eventMonitorHandler.OnHandleEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Key_002
 * @tc.desc: Test OnHandleEvent with key event without monitor flag
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Key_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->ClearFlag(InputEvent::EVENT_FLAG_NO_MONITOR);
    
    bool result = eventMonitorHandler.OnHandleEvent(keyEvent);
    // Expect false because no monitors are registered by default
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Pointer_001
 * @tc.desc: Test OnHandleEvent with pointer event having no monitor flag
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Pointer_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_MONITOR);
    
    bool result = eventMonitorHandler.OnHandleEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Pointer_002
 * @tc.desc: Test OnHandleEvent with pointer event without monitor flag
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Pointer_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->ClearFlag(InputEvent::EVENT_FLAG_NO_MONITOR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    
    bool result = eventMonitorHandler.OnHandleEvent(pointerEvent);
    // Expect false because no monitors are registered by default
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_InitSessionLostCallback_001
 * @tc.desc: Test InitSessionLostCallback idempotency
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_InitSessionLostCallback_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    
    // Call twice - should not crash
    eventMonitorHandler.InitSessionLostCallback();
    eventMonitorHandler.InitSessionLostCallback();
    
    // Reset and call again
    eventMonitorHandler.sessionLostCallbackInitialized_ = false;
    eventMonitorHandler.InitSessionLostCallback();
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnSessionLost_001
 * @tc.desc: Test OnSessionLost with valid session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnSessionLost_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnSessionLost_002
 * @tc.desc: Test OnSessionLost with null session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnSessionLost_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = nullptr;
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session));
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: EventMonitorHandlerNewTest_HandleKeyEvent_001
 * @tc.desc: Test HandleKeyEvent with null event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleKeyEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleKeyEvent_002
 * @tc.desc: Test HandleKeyEvent with valid event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleKeyEvent_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleKeyEvent(keyEvent));
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
/**
 * @tc.name: EventMonitorHandlerNewTest_HandlePointerEvent_001
 * @tc.desc: Test HandlePointerEvent with null event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandlePointerEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandlePointerEvent_002
 * @tc.desc: Test HandlePointerEvent with valid event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandlePointerEvent_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandlePointerEvent(pointerEvent));
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_001
 * @tc.desc: Test HandleTouchEvent with null event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_002
 * @tc.desc: Test HandleTouchEvent with valid touch event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_002, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_003
 * @tc.desc: Test HandleTouchEvent with knuckle event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_003, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(1);
    
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->AddPointerItem(item);
    
    // Should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}
#endif // OHOS_BUILD_ENABLE_TOUCH

/**
 * @tc.name: EventMonitorHandlerNewTest_ProcessScreenCapture_001
 * @tc.desc: Test ProcessScreenCapture when PLAYER_FRAMEWORK_EXISTS is not defined
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_ProcessScreenCapture_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    
    // Should not crash when PLAYER_FRAMEWORK_EXISTS is not defined
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(1234, true));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(1234, false));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_NullCallback_001
 * @tc.desc: Test AddInputHandler with nullptr callback returns error
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_NullCallback_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    std::shared_ptr<IInputEventHandler::IInputEventConsumer> callback = nullptr;
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;

    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_CombinedEvent_001
 * @tc.desc: Test AddInputHandler with KEY|POINTER combined event type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_CombinedEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY | HANDLE_EVENT_TYPE_POINTER;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;

    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);

    bool hasKey = eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY);
    EXPECT_TRUE(hasKey);
    bool hasPointer = eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_POINTER);
    EXPECT_TRUE(hasPointer);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_AllEvents_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_ALL
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_AllEvents_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_ALL;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;

    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Interceptor_001
 * @tc.desc: Test AddInputHandler with INTERCEPTOR handler type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_Interceptor_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    auto callback = std::make_shared<MockInputEventConsumer>();
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t fingers = 0;

    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, eventType, callback, gestureType, fingers);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_MultipleCallbacks_001
 * @tc.desc: Test adding multiple callbacks for different event types
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_MultipleCallbacks_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret1 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, session1, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret1, RET_OK);

    int32_t ret2 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_POINTER, session2, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret2, RET_OK);

    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_POINTER));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_SameCallbackDifferentType_001
 * @tc.desc: Test adding same callback with different event types
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_SameCallbackDifferentType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret1 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, session1, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret1, RET_OK);

    int32_t ret2 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_POINTER, session2, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret2, RET_OK);

    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_POINTER));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_NonExistent_001
 * @tc.desc: Test RemoveInputHandler with non-existent handler - no crash
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_NonExistent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_NONE, 0));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_NullCallback_001
 * @tc.desc: Test RemoveInputHandler with null callback - no crash
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_NullCallback_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<IInputEventHandler::IInputEventConsumer> callback = nullptr;

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_NONE, 0));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_NonExistentSession_001
 * @tc.desc: Test RemoveInputHandler with non-existent session - no crash
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_NonExistentSession_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, session, TOUCH_GESTURE_TYPE_NONE, 0));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_NonExistentActions_001
 * @tc.desc: Test RemoveInputHandler with non-existent actions handler
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_NonExistentActions_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::vector<int32_t> actionsType = {PointerEvent::POINTER_ACTION_DOWN};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR, actionsType, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_VerifyRemoval_001
 * @tc.desc: Test removal and verify CheckHasInputHandler returns false
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_VerifyRemoval_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        session, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));

    std::vector<int32_t> emptyActions;
    eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR, emptyActions, session);
    EXPECT_FALSE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_GestureSwipe_001
 * @tc.desc: Test AddInputHandler with three finger swipe gesture
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_GestureSwipe_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_SWIPE, 3);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_GesturePinch_001
 * @tc.desc: Test AddInputHandler with pinch gesture
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_GesturePinch_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_PINCH, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_GestureRotate_001
 * @tc.desc: Test AddInputHandler with rotate gesture
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_GestureRotate_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_PINCH, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_GestureFourSwipe_001
 * @tc.desc: Test AddInputHandler with four finger swipe gesture
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_GestureFourSwipe_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_SWIPE, 4);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_GestureThreeTap_001
 * @tc.desc: Test AddInputHandler with three finger tap gesture
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_GestureThreeTap_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_PINCH, 3);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_CheckHasInputHandler_MultipleTypes_001
 * @tc.desc: Test CheckHasInputHandler returns correct results for different types
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_CheckHasInputHandler_MultipleTypes_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        callback, TOUCH_GESTURE_TYPE_NONE, 0);

    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
    EXPECT_FALSE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_POINTER));
    EXPECT_FALSE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_TOUCH));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_CheckHasInputHandler_NoneType_001
 * @tc.desc: Test CheckHasInputHandler with HANDLE_EVENT_TYPE_NONE
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_CheckHasInputHandler_NoneType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;

    bool result = eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_NONE);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_MarkConsumed_NonExistentEvent_001
 * @tc.desc: Test MarkConsumed with non-existent event ID
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_MarkConsumed_NonExistentEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t eventId = 99999;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        session, TOUCH_GESTURE_TYPE_NONE, 0);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_MarkConsumed_DoubleMark_001
 * @tc.desc: Test MarkConsumed twice with same event - no crash
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_MarkConsumed_DoubleMark_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t eventId = 200;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        session, TOUCH_GESTURE_TYPE_NONE, 0);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Key_WithHandler_001
 * @tc.desc: Test OnHandleEvent with key event when no handlers registered
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Key_WithHandler_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    bool result = eventMonitorHandler.OnHandleEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Pointer_MouseSource_001
 * @tc.desc: Test OnHandleEvent with pointer event from mouse source
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Pointer_MouseSource_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    bool result = eventMonitorHandler.OnHandleEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandlePointerEvent_Touchpad_001
 * @tc.desc: Test HandlePointerEvent with touchpad source
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandlePointerEvent_Touchpad_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_Finger_001
 * @tc.desc: Test HandleTouchEvent with finger tool type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_Finger_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(1);

    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->AddPointerItem(item);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_Pen_001
 * @tc.desc: Test HandleTouchEvent with pen tool type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_Pen_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(1);

    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerEvent->AddPointerItem(item);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_ActionsEmpty_001
 * @tc.desc: Test AddInputHandler with empty actions vector
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_ActionsEmpty_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    std::vector<int32_t> actionsType = {};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, actionsType, session);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_ActionsSingle_001
 * @tc.desc: Test AddInputHandler with single action
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_ActionsSingle_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    std::vector<int32_t> actionsType = {PointerEvent::POINTER_ACTION_DOWN};
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, actionsType, session);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_ActionsMany_001
 * @tc.desc: Test AddInputHandler with many different actions
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_ActionsMany_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    std::vector<int32_t> actionsType = {
        PointerEvent::POINTER_ACTION_DOWN,
        PointerEvent::POINTER_ACTION_UP,
        PointerEvent::POINTER_ACTION_MOVE,
        PointerEvent::POINTER_ACTION_CANCEL
    };
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret = eventMonitorHandler.AddInputHandler(handlerType, actionsType, session);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_Dump_WithArgs_001
 * @tc.desc: Test Dump with multiple args
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_Dump_WithArgs_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t fd = 1;
    std::vector<std::string> args = {"-monitor", "--verbose"};

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.Dump(fd, args));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_Dump_WithNegativeFd_001
 * @tc.desc: Test Dump with negative fd
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_Dump_WithNegativeFd_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t fd = -1;
    std::vector<std::string> args;

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.Dump(fd, args));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_GetMonitorCollection_AfterAdd_001
 * @tc.desc: Test GetMonitorCollection after adding handlers
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_GetMonitorCollection_AfterAdd_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        callback, TOUCH_GESTURE_TYPE_NONE, 0);

    const ISessionHandlerCollection* collection = eventMonitorHandler.GetMonitorCollection();
    EXPECT_NE(collection, nullptr);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnSessionLost_WithHandler_001
 * @tc.desc: Test OnSessionLost with session that was registered
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnSessionLost_WithHandler_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        session, TOUCH_GESTURE_TYPE_NONE, 0);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnSessionLost_MultipleSessions_001
 * @tc.desc: Test OnSessionLost with multiple registered sessions
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnSessionLost_MultipleSessions_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        session1, TOUCH_GESTURE_TYPE_NONE, 0);
    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_POINTER,
        session2, TOUCH_GESTURE_TYPE_NONE, 0);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session1));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.OnSessionLost(session2));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleKeyEvent_WithMonitor_001
 * @tc.desc: Test HandleKeyEvent with registered monitor
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleKeyEvent_WithMonitor_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_SessionWithGesture_001
 * @tc.desc: Test AddInputHandler with session and gesture type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_SessionWithGesture_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, session, TOUCH_GESTURE_TYPE_SWIPE, 3);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_SessionInvalidNoCrash_001
 * @tc.desc: Test AddInputHandler with various invalid inputs
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_SessionInvalidNoCrash_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = nullptr;

    int32_t ret1 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, session, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_NE(ret1, RET_OK);

    SessionPtr nullSession = nullptr;
    ret1 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_NONE, nullSession, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_NE(ret1, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_ProcessScreenCapture_WithHandler_001
 * @tc.desc: Test ProcessScreenCapture start/stop cycle
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_ProcessScreenCapture_WithHandler_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(5678, true));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(5678, false));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_SessionWithMultipleEventTypes_001
 * @tc.desc: Test AddInputHandler with session for multiple event types
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_SessionWithMultipleEventTypes_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret1 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY | HANDLE_EVENT_TYPE_POINTER, session, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret1, RET_OK);

    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_POINTER));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_AddRemoveReAdd_001
 * @tc.desc: Test add, remove, and re-add the same handler
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_AddRemoveReAdd_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret1 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret1, RET_OK);

    eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_NONE, 0);

    int32_t ret2 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleKeyEvent_NullEvent_001
 * @tc.desc: Test HandleKeyEvent with null key event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleKeyEvent_NullEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleKeyEvent_CreatedEvent_001
 * @tc.desc: Test HandleKeyEvent with created event and key code
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleKeyEvent_CreatedEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandlePointerEvent_NullEvent_001
 * @tc.desc: Test HandlePointerEvent with null pointer event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandlePointerEvent_NullEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_NullEvent_001
 * @tc.desc: Test HandleTouchEvent with null pointer event
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_NullEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_TouchGestureAction_001
 * @tc.desc: Test HandleTouchEvent with touch gesture action (Swipe)
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_TouchGestureAction_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_MarkConsumed_NoSession_001
 * @tc.desc: Test MarkConsumed without adding a session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_MarkConsumed_NoSession_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t eventId = 300;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Pointer_NoMonitors_001
 * @tc.desc: Test OnHandleEvent pointer without monitors
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Pointer_NoMonitors_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->ClearFlag(InputEvent::EVENT_FLAG_NO_MONITOR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    bool result = eventMonitorHandler.OnHandleEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Pointer_NoMonitorFlag_001
 * @tc.desc: Test OnHandleEvent pointer with no monitor flag set
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Pointer_NoMonitorFlag_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_MONITOR);

    bool result = eventMonitorHandler.OnHandleEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_CheckHasInputHandler_AfterRemoveAll_001
 * @tc.desc: Test CheckHasInputHandler after removing all handlers
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_CheckHasInputHandler_AfterRemoveAll_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        session1, TOUCH_GESTURE_TYPE_NONE, 0);
    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_POINTER,
        session2, TOUCH_GESTURE_TYPE_NONE, 0);

    std::vector<int32_t> emptyActions;
    eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR, emptyActions, session1);
    eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR, emptyActions, session2);

    EXPECT_FALSE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
    EXPECT_FALSE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_POINTER));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_CheckHasInputHandler_AfterPartialRemove_001
 * @tc.desc: Test CheckHasInputHandler after removing only one of two handlers
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_CheckHasInputHandler_AfterPartialRemove_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        session1, TOUCH_GESTURE_TYPE_NONE, 0);
    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_POINTER,
        session2, TOUCH_GESTURE_TYPE_NONE, 0);

    std::vector<int32_t> emptyActions;
    eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR, emptyActions, session1);

    EXPECT_FALSE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_POINTER));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_DuplicateSession_001
 * @tc.desc: Test AddInputHandler duplicate with same session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_DuplicateSession_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);

    int32_t ret1 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_KEY, session, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret1, RET_OK);

    int32_t ret2 = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_POINTER, session, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Key_NoHandler_001
 * @tc.desc: Test OnHandleEvent key without monitor flag
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Key_NoHandler_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->ClearFlag(InputEvent::EVENT_FLAG_NO_MONITOR);

    bool result = eventMonitorHandler.OnHandleEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandlePointerEvent_MouseSource_001
 * @tc.desc: Test HandlePointerEvent with mouse source type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandlePointerEvent_MouseSource_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_RemoveThenAddDifferentType_001
 * @tc.desc: Test removing then adding with different event type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_RemoveThenAddDifferentType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        callback, TOUCH_GESTURE_TYPE_NONE, 0);
    eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        callback, TOUCH_GESTURE_TYPE_NONE, 0);

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_POINTER,
        callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_MaxSessions_001
 * @tc.desc: Test adding many handlers to verify no crash at limit
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_MaxSessions_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;

    for (int32_t i = 0; i < 50; i++) {
        auto callback = std::make_shared<MockInputEventConsumer>();
        int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
            HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_NONE, 0);
        EXPECT_EQ(ret, RET_OK);
    }

    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_MouseType_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_MOUSE
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_MouseType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_MOUSE, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_TouchGestureType_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_TOUCH_GESTURE
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_TouchGestureType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_TOUCH_GESTURE, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_SwipeInward_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_SWIPEINWARD
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_SwipeInward_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_SWIPEINWARD, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_ThreeFingerSwipeType_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_THREEFINGERSSWIP
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_ThreeFingerSwipeType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_THREEFINGERSSWIP, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_FourFingerSwipeType_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_FOURFINGERSSWIP
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_FourFingerSwipeType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_FOURFINGERSSWIP, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_RotateType_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_ROTATE
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_RotateType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_ROTATE, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_PinchType_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_PINCH
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_PinchType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_PINCH, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_ThreeFingerTapType_001
 * @tc.desc: Test AddInputHandler with HANDLE_EVENT_TYPE_THREEFINGERSTAP
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_AddInputHandler_ThreeFingerTapType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    int32_t ret = eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR,
        HANDLE_EVENT_TYPE_THREEFINGERSTAP, callback, TOUCH_GESTURE_TYPE_NONE, 0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_WrongHandlerType_001
 * @tc.desc: Test RemoveInputHandler with non-MONITOR handler type
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_WrongHandlerType_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback = std::make_shared<MockInputEventConsumer>();

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        callback, TOUCH_GESTURE_TYPE_NONE, 0);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(InputHandlerType::INTERCEPTOR,
        HANDLE_EVENT_TYPE_KEY, callback, TOUCH_GESTURE_TYPE_NONE, 0));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_DifferentCallback_001
 * @tc.desc: Test RemoveInputHandler with different callback should not affect original
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_RemoveInputHandler_DifferentCallback_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto callback1 = std::make_shared<MockInputEventConsumer>();
    auto callback2 = std::make_shared<MockInputEventConsumer>();

    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        callback1, TOUCH_GESTURE_TYPE_NONE, 0);

    eventMonitorHandler.RemoveInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY,
        callback2, TOUCH_GESTURE_TYPE_NONE, 0);

    EXPECT_TRUE(eventMonitorHandler.CheckHasInputHandler(HANDLE_EVENT_TYPE_KEY));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleKeyEvent_FunctionKey_001
 * @tc.desc: Test HandleKeyEvent with function key
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleKeyEvent_FunctionKey_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandlePointerEvent_TouchGesture_001
 * @tc.desc: Test HandlePointerEvent with touch gesture action
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandlePointerEvent_TouchGesture_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_SwipeUpdate_001
 * @tc.desc: Test HandleTouchEvent with SWIPE_UPDATE action
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_SwipeUpdate_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_SwipeEnd_001
 * @tc.desc: Test HandleTouchEvent with SWIPE_END action
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_SwipeEnd_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_END);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_HandleTouchEvent_MultiplePointers_001
 * @tc.desc: Test HandleTouchEvent with multiple pointer items
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_HandleTouchEvent_MultiplePointers_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);

    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->AddPointerItem(item1);

    PointerEvent::PointerItem item2;
    item2.SetPointerId(1);
    item2.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->AddPointerItem(item2);

    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_OnHandleEvent_Key_ForceMonitor_001
 * @tc.desc: Test OnHandleEvent key without NO_MONITOR flag
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest,
    EventMonitorHandlerNewTest_OnHandleEvent_Key_ForceMonitor_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->ClearFlag(InputEvent::EVENT_FLAG_NO_MONITOR);

    bool result = eventMonitorHandler.OnHandleEvent(keyEvent);
    EXPECT_FALSE(result);
}
} // namespace MMI
} // namespace OHOS
