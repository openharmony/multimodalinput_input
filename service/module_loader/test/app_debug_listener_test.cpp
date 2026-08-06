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

/**
 * @tc.name: AppDebugListener_OnAppDebugStarted_001
 * @tc.desc: Test OnAppDebugStarted with empty vector keeps pid at -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStarted_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStarted_002
 * @tc.desc: Test OnAppDebugStarted with a single pid sets it as debug pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStarted_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 1234;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 1234);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStarted_003
 * @tc.desc: Test OnAppDebugStarted with multiple pids takes the last one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStarted_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo firstInfo;
    firstInfo.pid = 100;
    startInfos.push_back(firstInfo);
    AppExecFwk::AppDebugInfo secondInfo;
    secondInfo.pid = 200;
    startInfos.push_back(secondInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 200);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_001
 * @tc.desc: Test OnAppDebugStoped with empty vector keeps debug pid unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 100;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_002
 * @tc.desc: Test OnAppDebugStoped with a non-matching pid keeps debug pid unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 100;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 200;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_003
 * @tc.desc: Test OnAppDebugStoped with the matching pid resets debug pid to -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 100;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 100;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_005
 * @tc.desc: Test OnAppDebugStoped when already reset keeps the pid at -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 100;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 100;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_006
 * @tc.desc: Test OnAppDebugStoped matching only the current pid in a mixed vector
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 200;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 200);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 100;
    stopInfos.push_back(stopInfo);
    stopInfo.pid = 200;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_GetAppDebugPid_002
 * @tc.desc: Test GetAppDebugPid reflects the full start/stop lifecycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_GetAppDebugPid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    EXPECT_EQ(listener.GetAppDebugPid(), -1);

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

/**
 * @tc.name: AppDebugListener_GetInstance_003
 * @tc.desc: Test GetInstance returns a usable singleton for debug pid tracking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_GetInstance_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *instance = AppDebugListener::GetInstance();
    ASSERT_NE(instance, nullptr);
    EXPECT_EQ(instance->GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStarted_004
 * @tc.desc: Test OnAppDebugStarted can restart debugging after OnAppDebugStoped resets the pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStarted_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 100;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 100;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);

    startInfos.clear();
    startInfo.pid = 300;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 300);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStarted_005
 * @tc.desc: Test OnAppDebugStarted with an empty vector keeps an already set pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStarted_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 100;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);

    std::vector<AppExecFwk::AppDebugInfo> emptyInfos;
    listener.OnAppDebugStarted(emptyInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 100);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStarted_006
 * @tc.desc: Test OnAppDebugStarted with a negative pid is stored and reported as-is
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStarted_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = -1;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_007
 * @tc.desc: Test OnAppDebugStoped resets the pid when the matching entry is in the middle of the vector
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 300;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 300);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo firstInfo;
    firstInfo.pid = 100;
    stopInfos.push_back(firstInfo);
    AppExecFwk::AppDebugInfo secondInfo;
    secondInfo.pid = 300;
    stopInfos.push_back(secondInfo);
    AppExecFwk::AppDebugInfo thirdInfo;
    thirdInfo.pid = 200;
    stopInfos.push_back(thirdInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_008
 * @tc.desc: Test OnAppDebugStoped with duplicate matching entries stays reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo startInfo;
    startInfo.pid = 400;
    startInfos.push_back(startInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 400);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 400;
    stopInfos.push_back(stopInfo);
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);

    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_OnAppDebugStoped_009
 * @tc.desc: Test OnAppDebugStoped with a previously overwritten pid does not reset the current pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_OnAppDebugStoped_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo firstInfo;
    firstInfo.pid = 100;
    startInfos.push_back(firstInfo);
    AppExecFwk::AppDebugInfo secondInfo;
    secondInfo.pid = 200;
    startInfos.push_back(secondInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 200);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 100;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 200);

    stopInfo.pid = 200;
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}

/**
 * @tc.name: AppDebugListener_GetAppDebugPid_003
 * @tc.desc: Test GetAppDebugPid reports the current pid through a start, partial stop and full stop sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppDebugListenerTest, AppDebugListener_GetAppDebugPid_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    EXPECT_EQ(listener.GetAppDebugPid(), -1);

    std::vector<AppExecFwk::AppDebugInfo> startInfos;
    AppExecFwk::AppDebugInfo firstInfo;
    firstInfo.pid = 100;
    startInfos.push_back(firstInfo);
    AppExecFwk::AppDebugInfo secondInfo;
    secondInfo.pid = 200;
    startInfos.push_back(secondInfo);
    AppExecFwk::AppDebugInfo thirdInfo;
    thirdInfo.pid = 300;
    startInfos.push_back(thirdInfo);
    listener.OnAppDebugStarted(startInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 300);

    std::vector<AppExecFwk::AppDebugInfo> stopInfos;
    AppExecFwk::AppDebugInfo stopInfo;
    stopInfo.pid = 100;
    stopInfos.push_back(stopInfo);
    stopInfo.pid = 200;
    stopInfos.push_back(stopInfo);
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), 300);

    stopInfo.pid = 300;
    listener.OnAppDebugStoped(stopInfos);
    EXPECT_EQ(listener.GetAppDebugPid(), -1);
}
} // namespace MMI
} // namespace OHOS
