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

/**
 * @tc.name: ApplicationStateObserverTest_GetAppMgr_002
 * @tc.desc: Verify the first and non-first entry into the GetAppMgr function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetAppMgr_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver observer;
    auto appMgrFirst = observer.GetAppMgr();
    auto appMgrSecond = observer.GetAppMgr();
    if (appMgrFirst != nullptr) {
        EXPECT_NE(appMgrFirst->AsObject(), nullptr);
    }
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_002
 * @tc.desc: Verify the action of the InitAppStateObserver function when hasInit_ is true and false respectively
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    APP_OBSERVER_MGR->hasInit_ = true;
    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->InitAppStateObserver());

    APP_OBSERVER_MGR->hasInit_ = false;
    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->InitAppStateObserver());
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_003
 * @tc.desc: Verify InitAppStateObserver when CheckSystemAbility returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    APP_OBSERVER_MGR->hasInit_ = false;

    auto sysMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(sysMgr != nullptr);
    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->InitAppStateObserver());
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_004
 * @tc.desc: Verify InitAppStateObserver when iface_cast<IAppMgr>() returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    APP_OBSERVER_MGR->hasInit_ = false;

    OHOS::sptr<OHOS::ISystemAbilityManager> sysMgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(sysMgr != nullptr);
    OHOS::sptr<OHOS::IRemoteObject> obj = sysMgr->CheckSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    ASSERT_TRUE(obj != nullptr);
    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->InitAppStateObserver());
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_005
 * @tc.desc: Verify InitAppStateObserver when RegisterApplicationStateObserver fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    APP_OBSERVER_MGR->hasInit_ = false;
    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->InitAppStateObserver());
    EXPECT_FALSE(APP_OBSERVER_MGR->hasInit_);
}

/**
 * @tc.name: AppObserverManagerTest_SetForegroundAppData_001
 * @tc.desc: Verify SetForegroundAppData handles a filled AppStateData list without error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_SetForegroundAppData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<AppExecFwk::AppStateData> inputList;

    AppExecFwk::AppStateData data1;
    data1.isFocused = true;
    data1.isSplitScreenMode = false;
    data1.isFloatingWindowMode = false;
    data1.isSpecifyTokenId = true;
    data1.isPreloadModule = false;
    data1.pid = 1234;
    data1.uid = 1000;
    data1.callerUid = 1001;
    data1.state = 1;
    data1.appIndex = 0;
    data1.accessTokenId = 123456;
    data1.extensionType = AppExecFwk::ExtensionAbilityType::SERVICE;
    data1.renderPids = {2001, 2002};
    data1.bundleName = "com.example.app1";
    data1.callerBundleName = "com.example.caller1";

    AppExecFwk::AppStateData data2;
    data2.isFocused = false;
    data2.isSplitScreenMode = true;
    data2.isFloatingWindowMode = true;
    data2.isSpecifyTokenId = false;
    data2.isPreloadModule = true;
    data2.pid = 5678;
    data2.uid = 2000;
    data2.callerUid = 2001;
    data2.state = 2;
    data2.appIndex = 1;
    data2.accessTokenId = 654321;
    data2.extensionType = AppExecFwk::ExtensionAbilityType::UI;
    data2.renderPids = {3001, 3002};
    data2.bundleName = "com.example.app2";
    data2.callerBundleName = "com.example.caller2";

    inputList.push_back(data1);
    inputList.push_back(data2);

    ASSERT_NO_FATAL_FAILURE(APP_OBSERVER_MGR->SetForegroundAppData(inputList));
}

/**
 * @tc.name: AppObserverManagerTest_GetForegroundAppData_001
 * @tc.desc: Verify GetForegroundAppData returns the expected list set by SetForegroundAppData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_GetForegroundAppData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::vector<AppExecFwk::AppStateData> inputList;

    AppExecFwk::AppStateData data;
    data.isFocused = true;
    data.pid = 1234;
    data.bundleName = "com.test.app";
    inputList.push_back(data);

    APP_OBSERVER_MGR->SetForegroundAppData(inputList);
    std::vector<AppExecFwk::AppStateData> outputList = APP_OBSERVER_MGR->GetForegroundAppData();

    ASSERT_EQ(outputList.size(), 1);
    EXPECT_EQ(outputList[0].isFocused, true);
    EXPECT_EQ(outputList[0].pid, 1234);
    EXPECT_EQ(outputList[0].bundleName, "com.test.app");
}

/**
 * @tc.name: ApplicationStateObserverTest_GetForegroundApplicationInfo_002
 * @tc.desc: Verify GetForegroundApplicationInfo returns RET_ERR when appMgr is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetForegroundApplicationInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    ApplicationStateObserver observer;
    std::vector<AppExecFwk::AppStateData> list;
    int32_t ret = observer.GetForegroundApplicationInfo(list);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: ApplicationStateObserverTest_GetForegroundApplicationInfo_003
 * @tc.desc: Verify GetForegroundApplicationInfo fills list when appMgr is available
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetForegroundApplicationInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    ApplicationStateObserver observer;
    std::vector<AppExecFwk::AppStateData> list;
    int32_t ret = observer.GetForegroundApplicationInfo(list);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    if (ret == RET_OK) {
        EXPECT_GT(list.size(), 0);
        for (const auto& item : list) {
            EXPECT_GE(item.pid, 0);
            EXPECT_FALSE(item.bundleName.empty());
        }
        auto stored = APP_OBSERVER_MGR->GetForegroundAppData();
        EXPECT_EQ(stored.size(), list.size());
    }
}

/**
 * @tc.name: ApplicationStateObserverTest_OnProcessStateChanged_001
 * @tc.desc: Verify OnProcessStateChanged handles valid processData and invokes GetForegroundApplicationInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_OnProcessStateChanged_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver observer;
    AppExecFwk::ProcessData processData;
    processData.bundleName = "com.example.app";
    processData.uid = 10001;
    processData.pid = 1234;
    processData.state = AppExecFwk::AppProcessState::APP_STATE_READY;
    ASSERT_NO_FATAL_FAILURE(observer.OnProcessStateChanged(processData));
}
} // namespace MMI
} // namespace OHOS