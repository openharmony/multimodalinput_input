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
    std::shared_ptr<KeyEvent>event = KeyEvent::Create();
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
    std::shared_ptr<PointerEvent>pointerEvent = PointerEvent::Create();
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
    std::shared_ptr<PointerEvent>pointerEvent = PointerEvent::Create();
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
    std::shared_ptr<KeyEvent>event = KeyEvent::Create();
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
    std::shared_ptr<PointerEvent>pointerEvent = PointerEvent::Create();
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
    std::shared_ptr<KeyEvent>KeyEvent = KeyEvent::Create();
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
    std::shared_ptr<PointerEvent>pointerEvent = PointerEvent::Create();
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
