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
#include "mmi_log.h"
#include "uds_server.h"

#define private public
#include "event_interceptor_handler.h"
#undef private


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
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
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent>pointerEvent = PointerEvent::Create();
    EXPECT_FALSE(handler.OnHandleEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_006
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_006, TestSize.Level1)
{
    EventInterceptorHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.InitSessionLostCallback());
}

/**
 * @tc.name: EventInterceptorHandler_Test_007
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_007, TestSize.Level1)
{
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
} // namespace MMI
} // namespace OHOS
