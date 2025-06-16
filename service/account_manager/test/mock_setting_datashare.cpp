/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "mmi_log.h"
#include "setting_datashare.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "mock_setting_datashare"

namespace OHOS {
namespace MMI {
std::shared_ptr<SettingDataShare> SettingDataShare::instance_ = nullptr;
std::mutex SettingDataShare::mutex_;

SettingDataShare::~SettingDataShare() {}

SettingDataShare& SettingDataShare::GetInstance(int32_t systemAbilityId)
{
    MMI_HILOGI("Mock SettingDataShare::GetInstance called");
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SettingDataShare>();
        }
    }
    return *instance_;
}

ErrCode SettingDataShare::GetBoolValue(const std::string& key, bool& value, const std::string &strUri)
{
    MMI_HILOGI("Mock SettingDataShare::GetBoolValue called");
    if (strcmp(key.c_str(), "invaild") == 0) return -1;
    return ERR_OK;
}

ErrCode SettingDataShare::GetIntValue(const std::string& key, int32_t& value, const std::string &strUri)
{
    MMI_HILOGI("Mock SettingDataShare::GetIntValue called");
    return ERR_OK;
}

ErrCode SettingDataShare::GetStringValue(const std::string& key, std::string& value, const std::string &strUri)
{
    MMI_HILOGI("Mock SettingDataShare::GetStringValue called");
    return ERR_OK;
}

sptr<SettingObserver> SettingDataShare::CreateObserver(const std::string& key, SettingObserver::UpdateFunc& func)
{
    MMI_HILOGI("Mock SettingDataShare::CreateObserver called");
    return nullptr;
}

ErrCode SettingDataShare::RegisterObserver(const sptr<SettingObserver>& observer, const std::string &strUri)
{
    MMI_HILOGI("Mock SettingDataShare::RegisterObserver called");
    return ERR_OK;
}

ErrCode SettingDataShare::UnregisterObserver(const sptr<SettingObserver>& observer, const std::string &strUri)
{
    MMI_HILOGI("Mock SettingDataShare::UnregisterObserver called");
    return ERR_OK;
}

} // namespace MMI
} // namespace OHOS
