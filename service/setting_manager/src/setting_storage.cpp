/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "setting_storage.h"

#include "account_manager.h"
#include "datashare_values_bucket.h"
#include "datashare_predicates.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "mmi_log.h"
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SettingStore"
#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MIN_DELAY { -1 };
constexpr int32_t TARGET_INDEX { 0 };
const std::string SETTING_COLUMN_KEYWORD { "KEYWORD" };
const std::string SETTING_COLUMN_VALUE { "VALUE" };
const std::string SETTING_DATA_URI_BASE {"datashare:///com.ohos.settingdata/entry/settingdata/USER_SETTINGDATA_"};
const std::string SETTING_URI_PROXY { "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true" };
const std::string SETTING_DATA_EXT_URI { "datashare:///com.ohos.settingsdata.DataAbility" };
} // namespace

// DataShareHelper::Create is used for blocking synchronization and needs to be invoked after the database is ready
std::shared_ptr<DataShare::DataShareHelper> SettingStorage::CreateHelper()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MMI_HILOGE("saManager is null");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(MULTIMODAL_INPUT_SERVICE_ID);
    if (remoteObj == nullptr) {
        MMI_HILOGE("remoteObj is null");
        return nullptr;
    }
    auto [status, helper] = DataShare::DataShareHelper::Create(remoteObj,
        SETTING_URI_PROXY, SETTING_DATA_EXT_URI.c_str());
    if (status != RET_OK || helper == nullptr) {
        MMI_HILOGE("DataShareHelper creation failed");
        return nullptr;
    }
    return helper;
}

std::shared_ptr<DataShare::DataShareHelper> SettingStorage::GetHelper()
{
    std::lock_guard<std::recursive_mutex> lock(helperMutex_);
    if (helper_ == nullptr) {
        helper_ = CreateHelper();
    }
    return helper_;
}

SettingStorage::~SettingStorage()
{
    MMI_HILOGD("~SettingStorage, release helper");
    ReleaseDataShareHelper();
}

void SettingStorage::ReleaseDataShareHelper()
{
    MMI_HILOGD("Release helper");
    std::lock_guard<std::recursive_mutex> lock(helperMutex_);
    if (helper_ == nullptr) {
        MMI_HILOGE("helper is null, no need release");
        return;
    }
    if (!helper_->Release()) {
        MMI_HILOGE("helper release false");
    }
}

std::string SettingStorage::AssembleUriUser(int32_t userId, const std::string &key) const
{
    std::string uri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_" +
        std::to_string(userId) + "?Proxy=true&key=" + key;
    return uri;
}


bool SettingStorage::Write(int32_t userId, const std::string& key, const std::string& value)
{
    if (key.empty() || value.empty() || (userId < 0)) {
        MMI_HILOGE("Invalid param, key:%{public}s, value:%{public}s", key.c_str(), value.c_str());
        return false;
    }
    return WriteDataInternal(userId, key, value);
}

bool SettingStorage::WriteDataInternal(int32_t userId, const std::string& key, const std::string& value)
{
    MMI_HILOGI("WriteDataInternal, id:%{private}d, key:%{public}s, value:%{public}s",
        userId, key.c_str(), value.c_str());
    DataShare::DataShareValueObject keyObj(key);
    DataShare::DataShareValueObject valueObj(value);
    DataShare::DataShareValuesBucket bucket;
    bucket.Put(SETTING_COLUMN_KEYWORD, keyObj);
    bucket.Put(SETTING_COLUMN_VALUE, valueObj);

    Uri uri(AssembleUriUser(userId, key));
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);

    auto dataShareHelper = GetHelper();
    if (dataShareHelper == nullptr) {
        MMI_HILOGE("Get dataShareHelper failed");
        return false;
    }
    if (dataShareHelper->Update(uri, predicates, bucket) <= 0) {
        dataShareHelper->Insert(uri, bucket);
    }
    dataShareHelper->NotifyChange(uri);
    return true;
}

bool SettingStorage::Read(int32_t userId, const std::string& key, std::string& value)
{
    if (key.empty() || (userId < 0)) {
        MMI_HILOGE("Invalid param, key:%{public}s", key.c_str());
        return false;
    }
    return ReadDataInternal(userId, key, value);
}

bool SettingStorage::ReadDataInternal(int32_t userId, const std::string& key, std::string& value)
{
    MMI_HILOGI("ReadDataInternal, id:%{private}d, key:%{public}s", userId, key.c_str());
    std::vector<std::string> columns = { SETTING_COLUMN_VALUE };
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri(AssembleUriUser(userId, key));

    auto dataShareHelper = GetHelper();
    if (dataShareHelper == nullptr) {
        MMI_HILOGE("Get dataShareHelper failed");
        return false;
    }
    auto resultSet = dataShareHelper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        MMI_HILOGE("The query result set is null");
        return false;
    }

    int32_t count = 0;
    if ((resultSet->GetRowCount(count) != RET_OK) || (count == 0)) {
        MMI_HILOGE("The query result set is empty, key:%{public}s", key.c_str());
        resultSet->Close();
        return false;
    }

    if (resultSet->GoToFirstRow() != RET_OK) {
        MMI_HILOGE("GoToFirstRow failed, key: %{public}s", key.c_str());
        resultSet->Close();
        return false;
    }

    std::string tempValue;
    if (resultSet->GetString(TARGET_INDEX, tempValue) != RET_OK) {
        MMI_HILOGE("GetString failed, key: %{public}s", key.c_str());
        resultSet->Close();
        return false;
    }
    resultSet->Close();
    value = std::move(tempValue);
    MMI_HILOGI("ReadDataInternal, id:%{private}d, key:%{public}s, value:%{public}s",
        userId, key.c_str(), value.c_str());
    return true;
}

bool SettingStorage::ReadBatch(int32_t userId, const std::vector<std::string>& keys,
                              std::unordered_map<std::string, std::string>& result)
{
    if (keys.empty()) {
        MMI_HILOGE("Keys is empty");
        return false;
    }

    // Clear output parameter to ensure clean result
    result.clear();

    MMI_HILOGI("ReadBatch, id:%{private}d, keys count:%{public}zu", userId, keys.size());

    // Build IN predicates for batch query
    DataShare::DataSharePredicates predicates;
    DataShare::MutliValue keyValues(keys);
    predicates.In(SETTING_COLUMN_KEYWORD, keyValues);

    // Use the first key's URI
    Uri uri(AssembleUriUser(userId, keys[0]));

    // Query both KEYWORD and VALUE columns
    std::vector<std::string> columns = { SETTING_COLUMN_KEYWORD, SETTING_COLUMN_VALUE };

    auto dataShareHelper = GetHelper();
    if (dataShareHelper == nullptr) {
        MMI_HILOGE("Get dataShareHelper failed");
        return false;
    }

    auto resultSet = dataShareHelper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        MMI_HILOGE("The query result set is null");
        return false;
    }

    int32_t count = 0;
    if ((resultSet->GetRowCount(count) != RET_OK) || (count == 0)) {
        MMI_HILOGI("The query result set is empty, count:%{public}d", count);
        resultSet->Close();
        return true;  // Return true with empty result
    }

    // Traverse the result set
    if (resultSet->GoToFirstRow() != RET_OK) {
        MMI_HILOGE("GoToFirstRow failed");
        resultSet->Close();
        return false;
    }

    do {
        std::string key, value;
        int keyIndex = 0;  // KEYWORD column index
        int valueIndex = 1;  // VALUE column index

        if (resultSet->GetString(keyIndex, key) == RET_OK &&
            resultSet->GetString(valueIndex, value) == RET_OK) {
            result[key] = value;
            MMI_HILOGI("ReadBatch, found key:%{public}s, value:%{public}s", key.c_str(), value.c_str());
        }
    } while (resultSet->GoToNextRow() == RET_OK);

    resultSet->Close();
    MMI_HILOGI("ReadBatch, id:%{private}d, found:%{public}zu keys", userId, result.size());
    return true;
}
}
}
