/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "setting_datashare.h"
#include "setting_observer.h"
#include "event_log_helper.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SettingDatashareTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class SettingDatashareTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

class SettingObserverTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: SettingDatashareTest_GetIntValue
 * @tc.desc: Test GetIntValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_GetIntValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    int32_t value = 123;
    ASSERT_NE(settingDataShare.GetIntValue(key, value), ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutIntValue
 * @tc.desc: Test PutIntValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutIntValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    int32_t value = 123;
    bool needNotify = true;
    ASSERT_EQ(settingDataShare.PutIntValue(key, value, needNotify), ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutLongValue
 * @tc.desc: Test PutLongValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutLongValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    int64_t value = 123;
    bool needNotify = true;
    ASSERT_EQ(settingDataShare.PutLongValue(key, value, needNotify), ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutBoolValue
 * @tc.desc: Test PutBoolValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutBoolValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    bool value = true;
    bool needNotify = true;
    ASSERT_EQ(settingDataShare.PutBoolValue(key, value, needNotify), ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_IsValidKey
 * @tc.desc: Test IsValidKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_IsValidKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    ASSERT_FALSE(settingDataShare.IsValidKey(key));
}

/**
 * @tc.name: SettingDatashareTest_ExecRegisterCb
 * @tc.desc: Test ExecRegisterCb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_ExecRegisterCb, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    sptr<SettingObserver> observer = nullptr;
    ASSERT_NO_FATAL_FAILURE(settingDataShare.ExecRegisterCb(observer));
}

/**
 * @tc.name: SettingDatashareTest_RegisterObserver
 * @tc.desc: Test RegisterObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_RegisterObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    sptr<SettingObserver> observer = new (std::nothrow) SettingObserver;
    ASSERT_NE(observer, nullptr);
    observer->key_ = "settingDateShare";
    std::string strUri = "strUri";
    settingDataShare.isDataShareReady_ = false;
    ASSERT_NE(settingDataShare.RegisterObserver(observer, strUri), RET_ERR);
    settingDataShare.isDataShareReady_ = true;
    ASSERT_NE(settingDataShare.RegisterObserver(observer, strUri), RET_ERR);
    delete(observer);
    observer = nullptr;
}

/**
 * @tc.name: SettingDatashareTest_UnregisterObserver
 * @tc.desc: Test UnregisterObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_UnregisterObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    sptr<SettingObserver> observer = new (std::nothrow) SettingObserver;
    ASSERT_NE(observer, nullptr);
    observer->key_ = "settingDateShare";
    std::string strUri = "strUri";
    settingDataShare.isDataShareReady_ = false;
    ASSERT_NE(settingDataShare.UnregisterObserver(observer, strUri), RET_ERR);
    settingDataShare.isDataShareReady_ = true;
    ASSERT_NE(settingDataShare.UnregisterObserver(observer, strUri), RET_ERR);
    delete(observer);
    observer = nullptr;
}

/**
 * @tc.name: SettingDatashareTest_PutStringValue
 * @tc.desc: Test PutStringValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutStringValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "settingDateShare";
    std::string value = "valueObj";
    bool needNotify = true;
    ASSERT_NE(settingDataShare.PutStringValue(key, value, needNotify), RET_ERR);
}

/**
 * @tc.name: SettingObserverTest_OnChange
 * @tc.desc: Test OnChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_OnChange, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingObserver observer;
    std::string key = "SettingObserver";
    observer.SetKey(key);
    observer.update_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(observer.OnChange());
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper
 * @tc.desc: Test CreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "createdatasharehelper";
    ASSERT_NO_FATAL_FAILURE(settingDataShare.CreateDataShareHelper(str));
    str = "";
    ASSERT_NO_FATAL_FAILURE(settingDataShare.CreateDataShareHelper(str));
}

/**
 * @tc.name: SettingObserverTest_AssembleUri
 * @tc.desc: Test AssembleUri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_AssembleUri, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string key = "";
    std::string strui = "";
    ASSERT_NO_FATAL_FAILURE(settingDataShare.AssembleUri(key, strui));

    key = "close_fingerprint_nav_event_key";
    ASSERT_NO_FATAL_FAILURE(settingDataShare.AssembleUri(key, strui));

    strui = "AssembleUri";
    ASSERT_NO_FATAL_FAILURE(settingDataShare.AssembleUri(key, strui));
}

/**
 * @tc.name: SettingObserverTest_CheckIfSettingsDataReady
 * @tc.desc: Test CheckIfSettingsDataReady
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CheckIfSettingsDataReady, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    settingDataShare.isDataShareReady_ = true;
    bool ret = false;
    ret = settingDataShare.CheckIfSettingsDataReady();
    ASSERT_TRUE(ret);

    settingDataShare.isDataShareReady_ = false;
    ret = settingDataShare.CheckIfSettingsDataReady();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SettingObserverTest_CheckIfSettingsDataReady
 * @tc.desc: Test CheckIfSettingsDataReady
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, CheckIfSettingsDataReadyTest1, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    settingDataShare.isDataShareReady_ = true;
    settingDataShare.remoteObj_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(settingDataShare.CheckIfSettingsDataReady());
}

/**
 * @tc.name: CheckIfSettingsUnregisterObserver20
 * @tc.desc: Test CheckIfSettingsDataReady
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, CheckIfSettingsUnregisterObserver20, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    settingDataShare.isDataShareReady_ = false;
    settingDataShare.remoteObj_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(settingDataShare.CheckIfSettingsDataReady());
}
} // namespace MMI
} // namespace OHOS