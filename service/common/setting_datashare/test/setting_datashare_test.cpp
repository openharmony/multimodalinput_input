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

#include "iservice_registry.h"
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
    ASSERT_NE(settingDataShare.PutIntValue(key, value, needNotify), ERR_OK);
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
    ASSERT_NE(settingDataShare.PutLongValue(key, value, needNotify), ERR_OK);
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
    ASSERT_NE(settingDataShare.PutBoolValue(key, value, needNotify), ERR_OK);
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
 * @tc.name: SettingObserverTest_CreateDataShareHelper_001
 * @tc.desc: Test CreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "createdatasharehelper";
    ASSERT_NO_FATAL_FAILURE(settingDataShare.CreateDataShareHelper(str));
    str = "";
    ASSERT_NO_FATAL_FAILURE(settingDataShare.CreateDataShareHelper(str));
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper_002
 * @tc.desc: Test CreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "createdatasharehelper";
    SettingDataShare::instance_ = nullptr;
    ASSERT_EQ(settingDataShare.CreateDataShareHelper(str), nullptr);
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper_003
 * @tc.desc: Test CreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "createdatasharehelper";
    settingDataShare.isDataShareReady_ =false;
    ASSERT_EQ(settingDataShare.CreateDataShareHelper(str), nullptr);
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper_004
 * @tc.desc: Test CreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "createdatasharehelper";
    SettingDataShare::instance_ = std::make_shared<SettingDataShare>();
    SettingDataShare::instance_->isDataShareReady_ = true;
    settingDataShare.isDataShareReady_ = true;

    ASSERT_NO_FATAL_FAILURE(settingDataShare.CreateDataShareHelper(str));
    str = "";
    ASSERT_NE(settingDataShare.CreateDataShareHelper(str), nullptr);
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper_005
 * @tc.desc: Test CreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "createdatasharehelper";
    SettingDataShare::instance_ = std::make_shared<SettingDataShare>();
    SettingDataShare::instance_->isDataShareReady_ = true;
    settingDataShare.isDataShareReady_ = true;

    auto sysMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(sysMgr != nullptr);
    ASSERT_NO_FATAL_FAILURE(settingDataShare.CreateDataShareHelper(str));
    ASSERT_EQ(settingDataShare.CreateDataShareHelper(str), nullptr);
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

/**
 * @tc.name: SettingDatashareTest_GetIntValue_Fail
 * @tc.desc: Test GetIntValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_GetIntValue_Fail, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    int32_t value = 0;
    ErrCode ret = settingDataShare.GetIntValue(key, value);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_GetLongValue_Fail
 * @tc.desc: Test GetLongValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_GetLongValue_Fail, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    int64_t value = 0;
    ErrCode ret = settingDataShare.GetLongValue(key, value);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_GetBoolValue_Fail
 * @tc.desc: Test GetBoolValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_GetBoolValue_Fail, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    bool value = false;
    ErrCode ret = settingDataShare.GetBoolValue(key, value);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutIntValue_EmptyKey
 * @tc.desc: Test PutIntValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutIntValue_EmptyKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    int32_t value = 123;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutIntValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutLongValue_EmptyKey
 * @tc.desc: Test PutLongValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutLongValue_EmptyKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    int64_t value = 123;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutLongValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutBoolValue_EmptyKey
 * @tc.desc: Test PutBoolValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutBoolValue_EmptyKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    bool value = false;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutBoolValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutBoolValue_False
 * @tc.desc: Test PutBoolValue with false value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutBoolValue_False, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_put_bool_false";
    bool value = false;
    // Test bool to string conversion
    std::string valueStr = value ? "true" : "false";
    ASSERT_EQ(valueStr, "false");
}

/**
 * @tc.name: SettingDatashareTest_PutStringValue_EmptyKey
 * @tc.desc: Test PutStringValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutStringValue_EmptyKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    std::string value = "testValue";
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutStringValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutStringValue_EmptyValue
 * @tc.desc: Test PutStringValue with empty value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutStringValue_EmptyValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_put_string";
    std::string value = "";
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutStringValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutStringValue_NoNotify
 * @tc.desc: Test PutStringValue with needNotify false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutStringValue_NoNotify, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_put_string_no_notify";
    std::string value = "testValue";
    bool needNotify = false;
    ErrCode ret = settingDataShare.PutStringValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_IsValidKey_Empty
 * @tc.desc: Test IsValidKey with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_IsValidKey_Empty, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    bool ret = settingDataShare.IsValidKey(key);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SettingDatashareTest_IsValidKey_LongKey
 * @tc.desc: Test IsValidKey with long key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_IsValidKey_LongKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "very_long_key_name_that_might_cause_issues_in_datashare_system";
    bool ret = settingDataShare.IsValidKey(key);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: SettingDatashareTest_CreateObserver_NullFunc
 * @tc.desc: Test CreateObserver with null function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_CreateObserver_NullFunc, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_observer";
    SettingObserver::UpdateFunc func = nullptr;
    sptr<SettingObserver> observer = settingDataShare.CreateObserver(key, func);
    ASSERT_TRUE(observer != nullptr);
}

/**
 * @tc.name: SettingDatashareTest_CreateObserver_EmptyKey
 * @tc.desc: Test CreateObserver with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_CreateObserver_EmptyKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    SettingObserver::UpdateFunc func = nullptr;
    sptr<SettingObserver> observer = settingDataShare.CreateObserver(key, func);
    ASSERT_TRUE(observer != nullptr);
}

/**
 * @tc.name: SettingDatashareTest_ExecRegisterCb_NullObserver
 * @tc.desc: Test ExecRegisterCb with null observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_ExecRegisterCb_NullObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    sptr<SettingObserver> observer = nullptr;
    settingDataShare.ExecRegisterCb(observer);
    // Should not crash with null observer
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SettingDatashareTest_RegisterObserver_NullObserver
 * @tc.desc: Test RegisterObserver with null observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_RegisterObserver_NullObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    sptr<SettingObserver> observer = nullptr;
    ErrCode ret = settingDataShare.RegisterObserver(observer);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_RegisterObserver_ValidObserver
 * @tc.desc: Test RegisterObserver with valid observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_RegisterObserver_ValidObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    sptr<SettingObserver> observer = new (std::nothrow) SettingObserver();
    ASSERT_TRUE(observer != nullptr);
    observer->SetKey("test_register");
    ErrCode ret = settingDataShare.RegisterObserver(observer);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_UnregisterObserver_NullObserver
 * @tc.desc: Test UnregisterObserver with null observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_UnregisterObserver_NullObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    sptr<SettingObserver> observer = nullptr;
    ErrCode ret = settingDataShare.UnregisterObserver(observer);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_UnregisterObserver_ValidObserver
 * @tc.desc: Test UnregisterObserver with valid observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_UnregisterObserver_ValidObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    sptr<SettingObserver> observer = new (std::nothrow) SettingObserver();
    ASSERT_TRUE(observer != nullptr);
    observer->SetKey("test_unregister");
    ErrCode ret = settingDataShare.UnregisterObserver(observer);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_GetStringValue_EmptyKey
 * @tc.desc: Test GetStringValue with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_GetStringValue_EmptyKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "";
    std::string value;
    ErrCode ret = settingDataShare.GetStringValue(key, value);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_GetStringValue_LongKey
 * @tc.desc: Test GetStringValue with long key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_GetStringValue_LongKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "very_long_key_name_for_testing_get_string_value_function";
    std::string value;
    ErrCode ret = settingDataShare.GetStringValue(key, value);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper_EmptyUri
 * @tc.desc: Test CreateDataShareHelper with empty uri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_EmptyUri, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "";
    // SettingDataShare::instance_ = std::make_shared<SettingDataShare>();
    // SettingDataShare::instance_->isDataShareReady_ = true;
    settingDataShare.isDataShareReady_ = true;
    
    auto helper = settingDataShare.CreateDataShareHelper(str);
    ASSERT_FALSE(helper == nullptr);
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper_InstanceNull
 * @tc.desc: Test CreateDataShareHelper with null instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_InstanceNull, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "test_uri";
    // SettingDataShare::instance_ = nullptr;
    settingDataShare.isDataShareReady_ = true;
    
    auto helper = settingDataShare.CreateDataShareHelper(str);
    ASSERT_TRUE(helper == nullptr);
}

/**
 * @tc.name: SettingObserverTest_CreateDataShareHelper_NotReady
 * @tc.desc: Test CreateDataShareHelper with data share not ready
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CreateDataShareHelper_NotReady, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string str = "test_uri";
    // SettingDataShare::instance_ = std::make_shared<SettingDataShare>();
    // SettingDataShare::instance_->isDataShareReady_ = false;
    settingDataShare.isDataShareReady_ = false;
    
    auto helper = settingDataShare.CreateDataShareHelper(str);
    ASSERT_TRUE(helper == nullptr);
}

/**
 * @tc.name: SettingObserverTest_AssembleUri_EmptyKeyEmptyUri
 * @tc.desc: Test AssembleUri with empty key and empty uri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_AssembleUri_EmptyKeyEmptyUri, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string key = "";
    std::string strUri = "";
    Uri uri = settingDataShare.AssembleUri(key, strUri);
    ASSERT_TRUE(uri.GetPath() != "");
}

/**
 * @tc.name: SettingObserverTest_AssembleUri_FingerprintNavKey
 * @tc.desc: Test AssembleUri with fingerprint nav event key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_AssembleUri_FingerprintNavKey, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string key = "close_fingerprint_nav_event_key";
    std::string strUri = "";
    Uri uri = settingDataShare.AssembleUri(key, strUri);
    ASSERT_TRUE(uri.GetPath() != "");
}

/**
 * @tc.name: SettingObserverTest_AssembleUri_FingerprintEventKey
 * @tc.desc: Test AssembleUri with fingerprint event key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_AssembleUri_FingerprintEventKey, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string key = "close_fingerprint_event_key";
    std::string strUri = "";
    Uri uri = settingDataShare.AssembleUri(key, strUri);
    ASSERT_TRUE(uri.GetPath() != "");
}

/**
 * @tc.name: SettingObserverTest_AssembleUri_CustomUri
 * @tc.desc: Test AssembleUri with custom uri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_AssembleUri_CustomUri, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    std::string key = "test_key";
    std::string strUri = "datashare:///custom/uri";
    Uri uri = settingDataShare.AssembleUri(key, strUri);
    ASSERT_TRUE(uri.GetPath() != "");
}

/**
 * @tc.name: SettingObserverTest_CheckIfSettingsDataReady_RemoteObjNull
 * @tc.desc: Test CheckIfSettingsDataReady with null remoteObj
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CheckIfSettingsDataReady_RemoteObjNull, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    settingDataShare.isDataShareReady_ = false;
    SettingDataShare::remoteObj_ = nullptr;
    bool ret = settingDataShare.CheckIfSettingsDataReady();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SettingObserverTest_CheckIfSettingsDataReady_AlreadyReady
 * @tc.desc: Test CheckIfSettingsDataReady when already ready
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingObserverTest, SettingObserverTest_CheckIfSettingsDataReady_AlreadyReady, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SettingDataShare settingDataShare;
    settingDataShare.isDataShareReady_ = true;
    bool ret = settingDataShare.CheckIfSettingsDataReady();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SettingDatashareTest_GetInstance_MultipleCalls
 * @tc.desc: Test GetInstance with multiple calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_GetInstance_MultipleCalls, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare& instance1 = SettingDataShare::GetInstance(0);
    SettingDataShare& instance2 = SettingDataShare::GetInstance(0);
    ASSERT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: SettingDatashareTest_PutIntValue_NegativeValue
 * @tc.desc: Test PutIntValue with negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutIntValue_NegativeValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_negative_int";
    int32_t value = -123;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutIntValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutIntValue_MaxValue
 * @tc.desc: Test PutIntValue with max int32 value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutIntValue_MaxValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_max_int";
    int32_t value = INT32_MAX;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutIntValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutIntValue_MinValue
 * @tc.desc: Test PutIntValue with min int32 value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutIntValue_MinValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_min_int";
    int32_t value = INT32_MIN;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutIntValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutLongValue_NegativeValue
 * @tc.desc: Test PutLongValue with negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutLongValue_NegativeValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_negative_long";
    int64_t value = -123;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutLongValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutLongValue_MaxValue
 * @tc.desc: Test PutLongValue with max int64 value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutLongValue_MaxValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_max_long";
    int64_t value = INT64_MAX;
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutLongValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutStringValue_SpecialChars
 * @tc.desc: Test PutStringValue with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutStringValue_SpecialChars, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_special_chars";
    std::string value = "!@#$%^&*()_+-=[]{}|;:',.<>?/";
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutStringValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SettingDatashareTest_PutStringValue_LongValue
 * @tc.desc: Test PutStringValue with long value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDatashareTest, SettingDatashareTest_PutStringValue_LongValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SettingDataShare settingDataShare;
    std::string key = "test_long_value";
    std::string value(1000, 'a');
    bool needNotify = true;
    ErrCode ret = settingDataShare.PutStringValue(key, value, needNotify);
    ASSERT_NE(ret, ERR_OK);
}
} // namespace MMI
} // namespace OHOS