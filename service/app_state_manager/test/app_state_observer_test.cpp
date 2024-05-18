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

#include "app_state_observer.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ApplicationStateObserverTest"
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
 * @tc.desc: Verify the SetForegroundAppData and GetForegroundAppData functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_ForegroundAppData_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> appDatas {};
    APP_OBSERVER_MGR->SetForegroundAppData(appDatas);
    auto result = APP_OBSERVER_MGR->GetForegroundAppData();
    EXPECT_EQ(appDatas.size(), result.size());
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_001
 * @tc.desc: Verify the action of the InitAppStateObserver function when hasInit_ is true and false respectively
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    APP_OBSERVER_MGR->hasInit_ = true;
    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->InitAppStateObserver());
    APP_OBSERVER_MGR->hasInit_ = false;
    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->InitAppStateObserver());
}

/**
 * @tc.name: ApplicationStateObserverTest_GetAppMgr_001
 * @tc.desc: Verify the first and non-first entry into the GetAppMgr function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetAppMgr_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver obsever;
    auto appManager = obsever.GetAppMgr();
    EXPECT_NE(appManager, nullptr);
    appManager = obsever.GetAppMgr();
    EXPECT_NE(appManager, nullptr);
}

/**
 * @tc.name: ApplicationStateObserverTest_GetForegroundApplicationInfo_001
 * @tc.desc: Verify the results of obtaining foreground application information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetForegroundApplicationInfo_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver obsever;
    std::vector<AppExecFwk::AppStateData> appDatas {};
    int32_t ret = obsever.GetForegroundApplicationInfo(appDatas);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_FALSE(appDatas.empty());
    auto appManager = obsever.GetAppMgr();
    EXPECT_NE(appManager, nullptr);
    std::vector<AppExecFwk::AppStateData> appStateDatas {};
    ret = obsever.GetForegroundApplicationInfo(appStateDatas);
    EXPECT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS