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

#include "setting_datashare.h"

#include <thread>

#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "datashare_values_bucket.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "mmi_log.h"
#include "rdb_errno.h"
#include "result_set.h"
#include "uri.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "setting_DataShare"

namespace OHOS {
namespace MMI {
std::shared_ptr<SettingDataShare> SettingDataShare::instance_ = nullptr;
std::mutex SettingDataShare::mutex_;
sptr<IRemoteObject> SettingDataShare::remoteObj_;
namespace {
const std::string SETTING_COLUMN_KEYWORD { "KEYWORD" };
const std::string SETTING_COLUMN_VALUE { "VALUE" };
const std::string SETTING_URI_PROXY { "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true" };
const std::string SETTINGS_DATA_EXT_URI { "datashare:///com.ohos.settingsdata.DataAbility" };
constexpr int32_t DECIMAL_BASE { 10 };
} // namespace

SettingDataShare::~SettingDataShare() {}

SettingDataShare& SettingDataShare::GetInstance(int32_t systemAbilityId)
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SettingDataShare>();
            Initialize(systemAbilityId);
        }
    }
    return *instance_;
}

ErrCode SettingDataShare::GetIntValue(const std::string& key, int32_t& value)
{
    int64_t valueLong;
    ErrCode ret = GetLongValue(key, valueLong);
    if (ret != ERR_OK) {
        MMI_HILOGE("Get int value fail");
        return ret;
    }
    value = static_cast<int32_t>(valueLong);
    return ERR_OK;
}

ErrCode SettingDataShare::GetLongValue(const std::string& key, int64_t& value)
{
    std::string valueStr;
    ErrCode ret = GetStringValue(key, valueStr);
    if (ret != ERR_OK) {
        MMI_HILOGE("Get long value fail");
        return ret;
    }
    value = static_cast<int64_t>(strtoll(valueStr.c_str(), nullptr, DECIMAL_BASE));
    return ERR_OK;
}

ErrCode SettingDataShare::GetBoolValue(const std::string& key, bool& value)
{
    std::string valueStr;
    ErrCode ret = GetStringValue(key, valueStr);
    if (ret != ERR_OK) {
        MMI_HILOGE("Get bool value fail");
        return ret;
    }
    value = (valueStr == "true");
    return ERR_OK;
}

ErrCode SettingDataShare::PutIntValue(const std::string& key, int32_t value, bool needNotify)
{
    return PutStringValue(key, std::to_string(value), needNotify);
}

ErrCode SettingDataShare::PutLongValue(const std::string& key, int64_t value, bool needNotify)
{
    return PutStringValue(key, std::to_string(value), needNotify);
}

ErrCode SettingDataShare::PutBoolValue(const std::string& key, bool value, bool needNotify)
{
    std::string valueStr = value ? "true" : "false";
    return PutStringValue(key, valueStr, needNotify);
}

bool SettingDataShare::IsValidKey(const std::string& key)
{
    std::string value;
    ErrCode ret = GetStringValue(key, value);
    return (ret != ERR_NAME_NOT_FOUND) && (!value.empty());
}

sptr<SettingObserver> SettingDataShare::CreateObserver(const std::string& key, SettingObserver::UpdateFunc& func)
{
    sptr<SettingObserver> observer = new (std::nothrow) SettingObserver();
    CHKPP(observer);
    observer->SetKey(key);
    observer->SetUpdateFunc(func);
    return observer;
}

void SettingDataShare::ExecRegisterCb(const sptr<SettingObserver>& observer)
{
    CHKPV(observer);
    observer->OnChange();
}

ErrCode SettingDataShare::RegisterObserver(const sptr<SettingObserver>& observer)
{
    CHKPR(observer, RET_ERR);
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto uri = AssembleUri(observer->GetKey());
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return ERR_NO_INIT;
    }
    helper->RegisterObserver(uri, observer);
    helper->NotifyChange(uri);
    std::thread execCb([this, observer] { this->ExecRegisterCb(observer); });
    execCb.detach();
    ReleaseDataShareHelper(helper);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    return ERR_OK;
}

ErrCode SettingDataShare::UnregisterObserver(const sptr<SettingObserver>& observer)
{
    CHKPR(observer, RET_ERR);
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto uri = AssembleUri(observer->GetKey());
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return ERR_NO_INIT;
    }
    helper->UnregisterObserver(uri, observer);
    ReleaseDataShareHelper(helper);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    return ERR_OK;
}

void SettingDataShare::Initialize(int32_t systemAbilityId)
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPV(sam);
    auto remoteObj = sam->CheckSystemAbility(systemAbilityId);
    CHKPV(remoteObj);
    remoteObj_ = remoteObj;
}

ErrCode SettingDataShare::GetStringValue(const std::string& key, std::string& value)
{
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return ERR_NO_INIT;
    }
    std::vector<std::string> columns = {SETTING_COLUMN_VALUE};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri(AssembleUri(key));
    auto resultSet = helper->Query(uri, predicates, columns);
    ReleaseDataShareHelper(helper);
    if (resultSet == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return ERR_INVALID_OPERATION;
    }
    int32_t count = 0;
    resultSet->GetRowCount(count);
    if (count == 0) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return ERR_NAME_NOT_FOUND;
    }
    const int32_t tmpRow = 0;
    resultSet->GoToRow(tmpRow);
    int32_t ret = resultSet->GetString(tmpRow, value);
    if (ret != NativeRdb::E_OK) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return ERR_INVALID_VALUE;
    }
    resultSet->Close();
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    return ERR_OK;
}

ErrCode SettingDataShare::PutStringValue(const std::string& key, const std::string& value, bool needNotify)
{
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return ERR_NO_INIT;
    }
    DataShare::DataShareValueObject keyObj(key);
    DataShare::DataShareValueObject valueObj(value);
    DataShare::DataShareValuesBucket bucket;
    bucket.Put(SETTING_COLUMN_KEYWORD, keyObj);
    bucket.Put(SETTING_COLUMN_VALUE, valueObj);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri(AssembleUri(key));
    if (helper->Update(uri, predicates, bucket) <= 0) {
        helper->Insert(uri, bucket);
    }
    if (needNotify) {
        helper->NotifyChange(AssembleUri(key));
    }
    ReleaseDataShareHelper(helper);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    return ERR_OK;
}

std::shared_ptr<DataShare::DataShareHelper> SettingDataShare::CreateDataShareHelper()
{
    auto helper = DataShare::DataShareHelper::Creator(remoteObj_, SETTING_URI_PROXY, SETTINGS_DATA_EXT_URI.c_str());
    CHKPP(helper);
    return helper;
}

bool SettingDataShare::ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper>& helper)
{
    if (!helper->Release()) {
        return false;
    }
    return true;
}

Uri SettingDataShare::AssembleUri(const std::string& key)
{
    Uri uri(SETTING_URI_PROXY + "&key=" + key);
    return uri;
}
}
} // namespace OHOS