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

#include <gtest/gtest.h>

#include "event_interceptor_handler.h"
#include "mmi_log.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT { 0 };
const std::string PROGRAM_NAME = "uds_sesion_test";
int32_t g_moduleType = 3;
int32_t g_pid = 0;
int32_t g_writeFd = -1;
} // namespace

class EventInterceptorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventInterceptorHandler_Test_001
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_002
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_003
 * @tc.desc: Test the function HandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_004
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_005
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_FALSE(handler.OnHandleEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_007
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    std::shared_ptr<KeyEvent> KeyEvent = KeyEvent::Create();
    bool ret = interceptorHandler.HandleEvent(KeyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_Test_008
 * @tc.desc: Test the function CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    uint32_t deviceTags = 4;
    bool ret = interceptorHandler.CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    deviceTags = 2;
    ret = interceptorHandler.CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ret = interceptorHandler.CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_Test_009
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_Test_010
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_01
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    for (int32_t i = 0; i < 20; i++) {
        interceptorHandler.interceptors_.push_back(interceptorSecond);
    }
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_02
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    for (int32_t i = 0; i < 20; i++) {
        interceptorHandler.interceptors_.push_back(interceptorFirst);
    }
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_03
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_04
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_01
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_02
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_03
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 1;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_04
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 1;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_OnSessionLost_01
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnSessionLost_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr session = sessionSecond;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    interceptorHandler.interceptors_.push_back(interceptor);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.OnSessionLost(sessionFirst));
}

/**
 * @tc.name: EventInterceptorHandler_OnSessionLost_02
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnSessionLost_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr session = sessionFirst;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    interceptorHandler.interceptors_.push_back(interceptor);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.OnSessionLost(sessionFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInputHandler_01
 * @tc.desc: Test AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInputHandler_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler interceptorHandler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(interceptorHandler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess), RET_ERR);
}

/**
 * @tc.name: EventInterceptorHandler_AddInputHandler_02
 * @tc.desc: Test AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInputHandler_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler interceptorHandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(interceptorHandler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess), RET_OK);
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInputHandler
 * @tc.desc: Test RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInputHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler interceptorHandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, sess));
}

/**
 * @tc.name: EventInterceptorHandler_AddInputHandler_001
 * @tc.desc: Test the function AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 2;
    uint32_t deviceTags = 3;
    int32_t ret = handler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess);
    EXPECT_EQ(ret, RET_ERR);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ret = handler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess);
    EXPECT_EQ(ret, RET_ERR);
    eventType = HANDLE_EVENT_TYPE_KEY;
    ret = handler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInputHandler_001
 * @tc.desc: Test the function RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 2;
    uint32_t deviceTags = 1;
    SessionPtr session = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
    session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInputHandler_002
 * @tc.desc: Test the function RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    int32_t priority = 2;
    uint32_t deviceTags = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
    handlerType = InputHandlerType::MONITOR;
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
}

/**
 * @tc.name: EventInterceptorHandler_InitSessionLostCallback_001
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_InitSessionLostCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    handler.sessionLostCallbackInitialized_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.InitSessionLostCallback());
    handler.sessionLostCallbackInitialized_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.InitSessionLostCallback());
}

/**
 * @tc.name: EventInterceptorHandler_SendToClient_keyEvent_001
 * @tc.desc: Test the function SendToClient,parameter is keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_SendToClient_keyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler sessionHandler { handlerType, eventType, priority, deviceTags, session };
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(keyEvent));
    keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandler_SendToClient_pointerEvent_001
 * @tc.desc: Test the function SendToClient,parameter is pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_SendToClient_pointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler sessionHandler { handlerType, eventType, priority, deviceTags, session };
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(pointerEvent));
    pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_OnSessionLost
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnSessionLost, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler interceptorHandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.OnSessionLost(sess));
}

/**
 * @tc.name: EventInterceptorHandler_Dump
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler interceptorHandler;
    int32_t fd = 1;
    std::vector<std::string> args = {"-i"};
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.Dump(fd, args));
}
} // namespace MMI
} // namespace OHOS
