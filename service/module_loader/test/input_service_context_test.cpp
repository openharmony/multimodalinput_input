/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "input_service_context.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputServiceContextTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputServiceContextTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

protected:
    InputServiceContext inputServiceContext_;
};

/**
 * @tc.name: InputServiceContext_GetDelegateInterface_001
 * @tc.desc: Test GetDelegateInterface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputServiceContextTest, InputServiceContext_GetDelegateInterface_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto delegateInterface = inputServiceContext_.GetDelegateInterface();
    EXPECT_EQ(delegateInterface, nullptr);
}

/**
 * @tc.name: InputServiceContext_GetUDSServer_001
 * @tc.desc: Test GetUDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputServiceContextTest, InputServiceContext_GetUDSServer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    IUdsServer* udsServer = nullptr;
    ASSERT_NO_FATAL_FAILURE(udsServer = inputServiceContext_.GetUDSServer());
    EXPECT_EQ(udsServer, nullptr);
}

/**
 * @tc.name: InputServiceContext_GetEventNormalizeHandler_001
 * @tc.desc: Test GetEventNormalizeHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputServiceContextTest, InputServiceContext_GetEventNormalizeHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto handler = inputServiceContext_.GetEventNormalizeHandler();
    EXPECT_EQ(handler, nullptr);
}

/**
 * @tc.name: InputServiceContext_GetMonitorHandler_001
 * @tc.desc: Test GetMonitorHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputServiceContextTest, InputServiceContext_GetMonitorHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto handler = inputServiceContext_.GetMonitorHandler();
    EXPECT_EQ(handler, nullptr);
}

/**
 * @tc.name: InputServiceContext_GetTimerManager_001
 * @tc.desc: Test GetTimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputServiceContextTest, InputServiceContext_GetTimerManager_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto timerManager = inputServiceContext_.GetTimerManager();
    EXPECT_NE(timerManager, nullptr);
}

/**
 * @tc.name: InputServiceContext_GetInputWindowsManager_001
 * @tc.desc: Test GetInputWindowsManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputServiceContextTest, InputServiceContext_GetInputWindowsManager_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto windowManager = inputServiceContext_.GetInputWindowsManager();
    EXPECT_NE(windowManager, nullptr);
}

/**
 * @tc.name: InputServiceContext_AttachDelegateInterface_001
 * @tc.desc: Test AttachDelegateInterface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputServiceContextTest, InputServiceContext_AttachDelegateInterface_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IDelegateInterface> delegate = nullptr;
    ASSERT_NO_FATAL_FAILURE(inputServiceContext_.AttachDelegateInterface(delegate));
    auto attachedDelegate = inputServiceContext_.GetDelegateInterface();
    EXPECT_EQ(attachedDelegate, nullptr);
}
} // namespace MMI
} // namespace OHOS