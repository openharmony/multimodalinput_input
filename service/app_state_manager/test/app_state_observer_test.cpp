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

#define private public
#include "app_state_observer.h"
#undef private

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class ApplicationStateObserverTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ApplicationStateObserverTest_ForegroundAppData_001
 * @tc.desc: Verify the SetForegroundAppData and GetForegroundAppData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_ForegroundAppData_001, TestSize.Level1)
{
    std::vector<AppExecFwk::AppStateData> list {};
    APP_OBSERVER_MGR->SetForegroundAppData(list);
    auto result = APP_OBSERVER_MGR->GetForegroundAppData();
    EXPECT_EQ(list.size(), result.size());
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_001
 * @tc.desc: Verify the InitAppStateObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_001, TestSize.Level1)
{
    APP_OBSERVER_MGR->hasInit_ = true;
    APP_OBSERVER_MGR->InitAppStateObserver();
    APP_OBSERVER_MGR->hasInit_ = false;
    APP_OBSERVER_MGR->InitAppStateObserver();
}

/**
 * @tc.name: ApplicationStateObserverTest_GetAppMgr_001
 * @tc.desc: Verify the GetAppMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetAppMgr_001, TestSize.Level1)
{
    ApplicationStateObserver obsever;
    auto appManager = obsever.GetAppMgr();
    EXPECT_NE(appManager, nullptr);
    appManager = obsever.GetAppMgr();
    EXPECT_NE(appManager, nullptr);
}

/**
 * @tc.name: ApplicationStateObserverTest_GetForegroundApplicationInfo_001
 * @tc.desc: Verify the GetForegroundApplicationInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetForegroundApplicationInfo_001, TestSize.Level1)
{
    ApplicationStateObserver obsever;
    std::vector<AppExecFwk::AppStateData> list {};
    int32_t ret = obsever.GetForegroundApplicationInfo(list);
    EXPECT_NE(ret, RET_OK);
    EXPECT_TRUE(list.empty());
    auto appManager = obsever.GetAppMgr();
    EXPECT_NE(appManager, nullptr);
    std::vector<AppExecFwk::AppStateData> list2 {};
    ret = obsever.GetForegroundApplicationInfo(list2);
    EXPECT_NE(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS