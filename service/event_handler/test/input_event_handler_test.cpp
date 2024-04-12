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

#include <gtest/gtest.h>
#include <libinput.h>

#include "input_event_handler.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "libinput.h"
#include "key_command_handler.h"
#include "timer_manager.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
};

/**
 * @tc.name: InputEventHandler_GetEventDispatchHandler_001
 * @tc.desc: Get event dispatch handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetEventDispatchHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetEventDispatchHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetFilterHandler_001
 * @tc.desc: Get filter handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetFilterHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetFilterHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetMonitorHandler_001
 * @tc.desc: Get monitor handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetMonitorHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetMonitorHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetKeyCommandHandler_001
 * @tc.desc: Get monitor handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetKeyCommandHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetKeyCommandHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetSwitchSubscriberHandler_001
 * @tc.desc: Get switch subscriber handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetSwitchSubscriberHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetSwitchSubscriberHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetSubscriberHandler_001
 * @tc.desc: Get subscriber handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetSubscriberHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetSubscriberHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetInterceptorHandler_001
 * @tc.desc: Get interceptor handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetInterceptorHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetInterceptorHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetEventNormalizeHandler_001
 * @tc.desc: Get eventNormalize handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetEventNormalizeHandler_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetEventNormalizeHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetUDSServer_001
 * @tc.desc: Get UDS server verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetUDSServer_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetUDSServer();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_BuildInputHandlerChain_001
 * @tc.desc: Build input handler chain verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_BuildInputHandlerChain_001, TestSize.Level1)
{
    UDSServer udsServer;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    ASSERT_NO_FATAL_FAILURE(inputHandler->Init(udsServer));
}

/**
 * @tc.name: InputEventHandler_OnEvent_001
 * @tc.desc: On event verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_OnEvent_001, TestSize.Level1)
{
    void* mockEvent = nullptr;
    int64_t mockFrameTime = 123456789;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    ASSERT_NO_FATAL_FAILURE(inputHandler->OnEvent(mockEvent, mockFrameTime));
}
} // namespace MMI
} // namespace OHOS