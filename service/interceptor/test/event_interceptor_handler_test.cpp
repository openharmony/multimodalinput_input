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
    bool ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    deviceTags = 2;
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
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
 * @tc.name: KeyInterceptByHostOSWhiteList_001
 * @tc.desc: Test the function KeyInterceptByHostOSWhiteList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, KeyInterceptByHostOSWhiteList_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    handler.keyevent_intercept_whitelist = nullptr;
    int32_t keyCode = 123;
    EXPECT_FALSE(handler.KeyInterceptByHostOSWhiteList(keyCode));
    handler.keyevent_intercept_whitelist = std::make_unique<std::string>("");
    EXPECT_FALSE(handler.KeyInterceptByHostOSWhiteList(keyCode));
}

/**
 * @tc.name: KeyInterceptByHostOSWhiteList_002
 * @tc.desc: Test the function KeyInterceptByHostOSWhiteList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, KeyInterceptByHostOSWhiteList_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    int32_t keyCode = 123;
    handler.keyevent_intercept_whitelist = std::make_unique<std::string>("123;456;");
    EXPECT_TRUE(handler.KeyInterceptByHostOSWhiteList(keyCode));
}

/**
 * @tc.name: KeyInterceptByHostOSWhiteList_003
 * @tc.desc: Test the function KeyInterceptByHostOSWhiteList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, KeyInterceptByHostOSWhiteList_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    int32_t keyCode = 789;
    handler.keyevent_intercept_whitelist = std::make_unique<std::string>("123;456;");
    EXPECT_FALSE(handler.KeyInterceptByHostOSWhiteList(keyCode));
}

/**
 * @tc.name: EventInterceptorHandler_Test_011
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    // SessionPtr session = std::make_shared<SessionPtr>();
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority, deviceTags, nullptr);
    interceptorHandler.interceptors_.push_back(sessionHandler);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TouchPadKnuckleDoubleClickHandle_Test_001
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, TouchPadKnuckleDoubleClickHandle_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->SetKeyAction(KNUCKLE_1F_DOUBLE_CLICK); // or KNUCKLE_2F_DOUBLE_CLICK
    EventInterceptorHandler handler;
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    bool result = handler.TouchPadKnuckleDoubleClickHandle(event);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TouchPadKnuckleDoubleClickHandle_Test_002
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, TouchPadKnuckleDoubleClickHandle_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    int32_t keyAction = 123;
    event->SetKeyAction(keyAction); // Not a double click action
    EventInterceptorHandler handler;
    bool result = handler.TouchPadKnuckleDoubleClickHandle(event);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TouchPadKnuckleDoubleClickHandle_Test_003
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, TouchPadKnuckleDoubleClickHandle_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK); // or KNUCKLE_2F_DOUBLE_CLICK
    EventInterceptorHandler handler;
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    bool result = handler.TouchPadKnuckleDoubleClickHandle(event);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0011
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0018
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    int32_t keyAction = 123;
    event->SetKeyAction(keyAction); // or KNUCKLE_2F_DOUBLE_CLICK
    EventInterceptorHandler handler;
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickHandle(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0019
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    InputEvent->ClearFlag();
    uint32_t flag = 1;
    InputEvent->AddFlag(flag);
    EventInterceptorHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}

static uint32_t TestCapabilityToTags(InputDeviceCapability capability)
{
    return static_cast<uint32_t>((1 << capability) - (capability / INPUT_DEV_CAP_MAX));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0020
 * @tc.desc: Test the function CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    uint32_t deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    bool ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TABLET_TOOL);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = 0;
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);

    pointerEvent->SetSourceType(0);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0021
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0021, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);
    ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0022
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0022, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_KEYBOARD;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, nullptr);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0023
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0023, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_TOUCH;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, nullptr);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0024
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0024, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_KEYBOARD;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    ASSERT_NO_FATAL_FAILURE(interceptorHandler.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0025
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0025, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_KEYBOARD;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0026
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0026, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0027
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0027, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, nullptr);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0028
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0028, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_POINTER;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: EventInterceptorHandler_HandleKeyEvent_002
 * @tc.desc: Test the function HandleKeyEvent WhenDoubleClickDetected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_HandleKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    event->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_HandleKeyEvent_003
 * @tc.desc: Test the function HandleKeyEvent WhenDoubleClickDetected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_HandleKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    event->SetKeyAction(KNUCKLE_1F_DOUBLE_CLICK);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_HandleKeyEvent_004
 * @tc.desc: Test the function HandleKeyEvent WhenKeyInWhiteList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_HandleKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    event->SetKeyAction(INPUT_DEVICE_AISENSOR);
    int32_t keyCode = 123;
    handler.keyevent_intercept_whitelist = std::make_unique<std::string>("123;456;");
    EXPECT_TRUE(handler.KeyInterceptByHostOSWhiteList(keyCode));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_HandleKeyEvent_005
 * @tc.desc: Test the function HandleKeyEvent WhenKeyNotInWhiteListAndNotOnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_HandleKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    event->SetKeyAction(INPUT_DEVICE_AISENSOR);
    handler.keyevent_intercept_whitelist = nullptr;
    int32_t keyCode = 123;
    EXPECT_FALSE(handler.KeyInterceptByHostOSWhiteList(keyCode));
    handler.keyevent_intercept_whitelist = std::make_unique<std::string>("");
    EXPECT_FALSE(handler.KeyInterceptByHostOSWhiteList(keyCode));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_HandleKeyEvent_006
 * @tc.desc: Test the function HandleKeyEvent WhenKeyNotInWhiteList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_HandleKeyEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    event->SetKeyAction(INPUT_DEVICE_AISENSOR);
    int32_t keyCode = 789;
    handler.keyevent_intercept_whitelist = std::make_unique<std::string>("123;456;");
    EXPECT_FALSE(handler.KeyInterceptByHostOSWhiteList(keyCode));
    event->bitwise_ = 0x00000000;
    EXPECT_FALSE(handler.OnHandleEvent(event));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_001
 * @tc.desc: Test the function OnHandleEvent_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->bitwise_ = 0x00000001;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_002
 * @tc.desc: Test the function OnHandleEvent_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->bitwise_ = 0x00000000;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_003
 * @tc.desc: Test the function OnHandleEvent_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->bitwise_ = 0x00000001;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_004
 * @tc.desc: Test the function OnHandleEvent_004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->bitwise_ = 0x0000000;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

} // namespace MMI
} // namespace OH