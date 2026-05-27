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

#include "app_debug_listener.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AppDebugListenerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}

class AppDebugListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: AppDebugListener_GetInstance_001
 * @tc.desc: Test GetInstance returns non-null singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_GetInstance_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *instance = AppDebugListener::GetInstance();
    ASSERT_NE(instance, nullptr);
}

/**
 * @tc.name: AppDebugListener_GetInstance_002
 * @tc.desc: Test GetInstance returns the same instance on multiple calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_GetInstance_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *instance1 = AppDebugListener::GetInstance();
    auto *instance2 = AppDebugListener::GetInstance();
    EXPECT_EQ(instance1, instance2);
}

/**
 * @tc.name: AppDebugListener_GetAppDebugPid_001
 * @tc.desc: Test GetAppDebugPid returns -1 by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_GetAppDebugPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_004
 * @tc.desc: Test OnAppDebugStoped after OnAppDebugStarted lifecycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 5678;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 5678);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 5678;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}
} // namespace MMI
} // namespace OHOS
