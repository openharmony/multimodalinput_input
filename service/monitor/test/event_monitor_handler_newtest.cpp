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
    void SetUp() override {
        // Reset singleton state to ensure clean state for each test
        EventMonitorHandler handler;
        handler.InitSessionLostCallback();
    }
    void TearDown() override {
        // Reset singleton state after each test
        EventMonitorHandler handler;
        handler.InitSessionLostCallback();
    }
};

/**
 * @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_001
 * @tc.desc: Test AddInputHandler with key event and callback
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_003, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_004, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Pointer_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Pointer_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Touch_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Actions_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Actions_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_RemoveInputHandler_Key_001, TestSize.Level1)
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
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(handlerType, eventType, callback, gestureType, fingers));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_Key_002
 * @tc.desc: Test RemoveInputHandler with key event and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_RemoveInputHandler_Key_002, TestSize.Level1)
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
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.RemoveInputHandler(handlerType, eventType, session, gestureType, fingers));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_RemoveInputHandler_Actions_001
 * @tc.desc: Test RemoveInputHandler with actions vector and session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_RemoveInputHandler_Actions_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_MarkConsumed_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    int32_t eventId = 100;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    
    // First add a handler for this session
    auto callback = std::make_shared<MockInputEventConsumer>();
    eventMonitorHandler.AddInputHandler(InputHandlerType::MONITOR, HANDLE_EVENT_TYPE_KEY, session, TOUCH_GESTURE_TYPE_NONE, 0);
    
    // Mark consumed - should not crash
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.MarkConsumed(eventId, session));
}

/**
 * @tc.name: EventMonitorHandlerNewTest_MarkConsumed_002
 * @tc.desc: Test MarkConsumed with invalid session
 * @tc.type: FUNC
 */
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_MarkConsumed_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_CheckHasInputHandler_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_CheckHasInputHandler_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_Dump_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_GetMonitorCollection_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_OnHandleEvent_Key_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_OnHandleEvent_Key_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_OnHandleEvent_Pointer_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_OnHandleEvent_Pointer_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_InitSessionLostCallback_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_OnSessionLost_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_OnSessionLost_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_HandleKeyEvent_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_HandleKeyEvent_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_HandlePointerEvent_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_HandlePointerEvent_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_HandleTouchEvent_001, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_HandleTouchEvent_002, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_HandleTouchEvent_003, TestSize.Level1)
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
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_ProcessScreenCapture_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    
    // Should not crash when PLAYER_FRAMEWORK_EXISTS is not defined
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(1234, true));
    ASSERT_NO_FATAL_FAILURE(eventMonitorHandler.ProcessScreenCapture(1234, false));
}

/**
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1000
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1000, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1001
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1001, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1002
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1002, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1003
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1003, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1004
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1004, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1005
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1005, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1006
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1006, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1007
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1007, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1008
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1008, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1009
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1009, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1010
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1010, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1011
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1011, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1012
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1012, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1013
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1013, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1014
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1014, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1015
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1015, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1016
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1016, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1017
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1017, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1018
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1018, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1019
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1019, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1020
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1020, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1021
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1021, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1022
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1022, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1023
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1023, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1024
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1024, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1025
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1025, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1026
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1026, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1027
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1027, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1028
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1028, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1029
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1029, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1030
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1030, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1031
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1031, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1032
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1032, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1033
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1033, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1034
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1034, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1035
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1035, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1036
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1036, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1037
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1037, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1038
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1038, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1039
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1039, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1040
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1040, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1041
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1041, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1042
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1042, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1043
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1043, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1044
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1044, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1045
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1045, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1046
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1046, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1047
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1047, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1048
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1048, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1049
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1049, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1050
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1050, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1051
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1051, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1052
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1052, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1053
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1053, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1054
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1054, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1055
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1055, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1056
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1056, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1057
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1057, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1058
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1058, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1059
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1059, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1060
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1060, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1061
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1061, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1062
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1062, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1063
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1063, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1064
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1064, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1065
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1065, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1066
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1066, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1067
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1067, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1068
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1068, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1069
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1069, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1070
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1070, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1071
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1071, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1072
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1072, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1073
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1073, TestSize.Level1)
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
* @tc.name: EventMonitorHandlerNewTest_AddInputHandler_Key_1074
* @tc.desc: Test AddInputHandler with key event and callback
* @tc.type: FUNC
*/
HWTEST_F(EventMonitorHandlerNewTest, EventMonitorHandlerNewTest_AddInputHandler_Key_1074, TestSize.Level1)
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

} // namespace MMI
} // namespace OHOS