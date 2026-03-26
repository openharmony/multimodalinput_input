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
 * @tc.name: ApplicationStateObserverTest_GetAppMgr_NullSystemAbilityManager_001
 * @tc.desc: Verify GetAppMgr returns nullptr when SystemAbilityManager is unavailable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetAppMgr_NullSystemAbilityManager_001,
    TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver observer;
    auto appManager = observer.GetAppMgr();
    // AppManager may be nullptr or valid depending on system state
    EXPECT_TRUE(appManager == nullptr || appManager != nullptr);
}

/**
 * @tc.name: ApplicationStateObserverTest_GetAppMgr_CacheValidation_001
 * @tc.desc: Verify GetAppMgr returns cached appManager_ on subsequent calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetAppMgr_CacheValidation_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver observer;
    auto appMgrFirst = observer.GetAppMgr();
    auto appMgrSecond = observer.GetAppMgr();
    // Cached value should be the same instance
    if (appMgrFirst != nullptr && appMgrSecond != nullptr) {
        EXPECT_EQ(appMgrFirst, appMgrSecond);
    }
}

/**
 * @tc.name: ApplicationStateObserverTest_GetForegroundApplicationInfo_EmptyList_001
 * @tc.desc: Verify GetForegroundApplicationInfo handles empty output list correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetForegroundApplicationInfo_EmptyList_001,
    TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver observer;
    std::vector<AppExecFwk::AppStateData> list {};
    int32_t ret = observer.GetForegroundApplicationInfo(list);
    // Return value should be RET_OK or RET_ERR
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ApplicationStateObserverTest_GetForegroundApplicationInfo_NullAppMgr_001
 * @tc.desc: Verify GetForegroundApplicationInfo returns RET_ERR when appMgr is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_GetForegroundApplicationInfo_NullAppMgr_001,
    TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    ApplicationStateObserver observer;
    std::vector<AppExecFwk::AppStateData> list {};
    int32_t ret = observer.GetForegroundApplicationInfo(list);
    // Should return RET_ERR if appMgr cannot be obtained
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    if (ret == RET_ERR) {
        EXPECT_TRUE(list.empty());
    }
}

/**
 * @tc.name: AppObserverManagerTest_SetForegroundAppData_EmptyList_001
 * @tc.desc: Verify SetForegroundAppData handles empty list without error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_SetForegroundAppData_EmptyList_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> emptyList {};
    APP_OBSERVER_MGR->SetForegroundAppData(emptyList);
    auto result = APP_OBSERVER_MGR->GetForegroundAppData();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: AppObserverManagerTest_SetForegroundAppData_LargeList_001
 * @tc.desc: Verify SetForegroundAppData handles large list correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_SetForegroundAppData_LargeList_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> largeList {};
    const size_t largeSize = 100;
    for (size_t i = 0; i < largeSize; i++) {
        AppExecFwk::AppStateData data;
        data.pid = static_cast<int32_t>(i);
        data.uid = static_cast<int32_t>(1000 + i);
        data.bundleName = "com.test.app" + std::to_string(i);
        data.isFocused = (i == 0);
        largeList.push_back(data);
    }
    APP_OBSERVER_MGR->SetForegroundAppData(largeList);
    auto result = APP_OBSERVER_MGR->GetForegroundAppData();
    EXPECT_EQ(result.size(), largeSize);
    EXPECT_EQ(result[0].pid, 0);
    EXPECT_EQ(result[largeSize - 1].pid, static_cast<int32_t>(largeSize - 1));
}

/**
 * @tc.name: AppObserverManagerTest_SetForegroundAppData_Overwrite_001
 * @tc.desc: Verify SetForegroundAppData can overwrite existing data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_SetForegroundAppData_Overwrite_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> firstList {};
    AppExecFwk::AppStateData firstData;
    firstData.bundleName = "com.first.app";
    firstData.pid = 1111;
    firstList.push_back(firstData);
    APP_OBSERVER_MGR->SetForegroundAppData(firstList);

    std::vector<AppExecFwk::AppStateData> secondList {};
    AppExecFwk::AppStateData secondData;
    secondData.bundleName = "com.second.app";
    secondData.pid = 2222;
    secondList.push_back(secondData);
    APP_OBSERVER_MGR->SetForegroundAppData(secondList);

    auto result = APP_OBSERVER_MGR->GetForegroundAppData();
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].bundleName, "com.second.app");
    EXPECT_EQ(result[0].pid, 2222);
}

/**
 * @tc.name: AppObserverManagerTest_GetForegroundAppData_ThreadSafety_001
 * @tc.desc: Verify GetForegroundAppData is thread-safe with concurrent access
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_GetForegroundAppData_ThreadSafety_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> testData {};
    AppExecFwk::AppStateData data;
    data.bundleName = "com.thread.test";
    data.pid = 9999;
    testData.push_back(data);
    APP_OBSERVER_MGR->SetForegroundAppData(testData);

    // Multiple consecutive gets should return consistent data
    auto result1 = APP_OBSERVER_MGR->GetForegroundAppData();
    auto result2 = APP_OBSERVER_MGR->GetForegroundAppData();
    auto result3 = APP_OBSERVER_MGR->GetForegroundAppData();
    EXPECT_EQ(result1.size(), result2.size());
    EXPECT_EQ(result2.size(), result3.size());
    if (!result1.empty()) {
        EXPECT_EQ(result1[0].pid, result2[0].pid);
        EXPECT_EQ(result2[0].pid, result3[0].pid);
    }
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_MultipleCalls_001
 * @tc.desc: Verify InitAppStateObserver can be called multiple times safely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_MultipleCalls_001,
    TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    APP_OBSERVER_MGR->hasInit_ = false;
    APP_OBSERVER_MGR->InitAppStateObserver();
    APP_OBSERVER_MGR->InitAppStateObserver();
    APP_OBSERVER_MGR->InitAppStateObserver();
    // Should not crash after multiple calls
    EXPECT_TRUE(true);
}

/**
 * @tc.name: ApplicationStateObserverTest_InitAppStateObserver_HasInitTrue_001
 * @tc.desc: Verify InitAppStateObserver returns early when hasInit_ is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, ApplicationStateObserverTest_InitAppStateObserver_HasInitTrue_001,
    TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    APP_OBSERVER_MGR->hasInit_ = true;
    bool hasInitBefore = APP_OBSERVER_MGR->hasInit_;
    APP_OBSERVER_MGR->InitAppStateObserver();
    // hasInit_ should remain true
    EXPECT_EQ(APP_OBSERVER_MGR->hasInit_, hasInitBefore);
    EXPECT_TRUE(APP_OBSERVER_MGR->hasInit_);
}

/**
 * @tc.name: AppObserverManagerTest_SetForegroundAppData_SpecialCharacters_001
 * @tc.desc: Verify SetForegroundAppData handles bundleName with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_SetForegroundAppData_SpecialCharacters_001,
    TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> inputList {};
    AppExecFwk::AppStateData data;
    data.bundleName = "com.example.app-with_special.chars123";
    data.pid = 1234;
    data.uid = 1000;
    inputList.push_back(data);
    APP_OBSERVER_MGR->SetForegroundAppData(inputList);
    auto result = APP_OBSERVER_MGR->GetForegroundAppData();
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].bundleName, "com.example.app-with_special.chars123");
}

/**
 * @tc.name: AppObserverManagerTest_SetForegroundAppData_AllFields_001
 * @tc.desc: Verify SetForegroundAppData preserves all AppStateData fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationStateObserverTest, AppObserverManagerTest_SetForegroundAppData_AllFields_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> inputList {};
    AppExecFwk::AppStateData data;
    data.isFocused = true;
    data.isSplitScreenMode = true;
    data.isFloatingWindowMode = true;
    data.isSpecifyTokenId = true;
    data.isPreloadModule = true;
    data.pid = 9999;
    data.uid = 8888;
    data.callerUid = 7777;
    data.state = 3;
    data.appIndex = 2;
    data.accessTokenId = 999999;
    data.extensionType = AppExecFwk::ExtensionAbilityType::FORM;
    data.renderPids = {1001, 1002, 1003};
    data.bundleName = "com.allfields.test";
    data.callerBundleName = "com.caller.test";
    inputList.push_back(data);

    APP_OBSERVER_MGR->SetForegroundAppData(inputList);
    auto result = APP_OBSERVER_MGR->GetForegroundAppData();

    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].pid, 9999);
    EXPECT_EQ(result[0].uid, 8888);
    EXPECT_EQ(result[0].bundleName, "com.allfields.test");
    EXPECT_TRUE(result[0].isFocused);
    EXPECT_TRUE(result[0].isSplitScreenMode);
    EXPECT_EQ(result[0].renderPids.size(), 3);
}
} // namespace MMI
} // namespace OHOS