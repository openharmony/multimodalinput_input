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

#include "whitelist_data_share_accessor.h"
 
#include "setting_datashare.h"
#include "setting_observer.h"
#include "mmi_log.h"

#include "ffrt.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "WhitelistDataShareAccessor"
 
namespace OHOS {
namespace MMI {
namespace {
const int32_t MULTIMODAL_INPUT_SERVICE_ID = 3101;
const std::string CONFIG_WHITELIST { "CONFIG_WHITELIST" };
const std::string SETTING_URI_PROXY { "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true" };
} // namespace
 
WhitelistDataShareAccessor& WhitelistDataShareAccessor::GetInstance()
{
    static WhitelistDataShareAccessor instance;
    return instance;
}

WhitelistDataShareAccessor::WhitelistDataShareAccessor()
{
    Init();
}

int32_t WhitelistDataShareAccessor::Init()
{
    // To avoid blocking the main thread; dispatch the task asynchronously.
    // In the worst case, the allowlist check for *IsWhitelisted* will be ineffective.
    CALL_INFO_TRACE;
    ffrt::submit([this] () {
        this->InitializeImpl();
    });
    return RET_OK;
}

int32_t WhitelistDataShareAccessor::InitializeImpl()
{
    CALL_INFO_TRACE;
    if (initialized_.load()) {
        MMI_HILOGE("Init already");
        return RET_OK;
    }
    std::vector<std::string> whitelist;
    if (ReadWhitelistFromDB(whitelist) != RET_OK) {
        MMI_HILOGE("ReadWhitelistFromDB failed");
        return RET_ERR;
    }
    UpdateWhitelist(whitelist);
    if (AddWhitelistObserver() != RET_OK) {
        MMI_HILOGE("ReadWhitelistFromDB failed");
        return RET_ERR;
    }
    initialized_.store(true);
    return RET_OK;
}
 
bool WhitelistDataShareAccessor::IsWhitelisted(const std::string &bundleName)
{
    if (!initialized_.load() && Init() != RET_OK) {
        MMI_HILOGE("Init failed");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(mtx_);
    return whitelist_.find(bundleName) != whitelist_.end();
}
 
int32_t WhitelistDataShareAccessor::ReadWhitelistFromDB(std::vector<std::string> &whitelist)
{
    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    std::string value;
    if (auto ret = settingHelper.GetStringValue(CONFIG_WHITELIST, value, SETTING_URI_PROXY); ret != RET_OK) {
        MMI_HILOGE("GetStringValue %{public}s failed, ret:%{public}d", CONFIG_WHITELIST.c_str(), ret);
        return RET_ERR;
    }
    MMI_HILOGI("Read whitelist: %{public}s", value.c_str());
    whitelist = Split(value);
    return RET_OK;
}
 
int32_t WhitelistDataShareAccessor::AddWhitelistObserver()
{
    auto &settingHelper = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID);
    SettingObserver::UpdateFunc updateFunc = [this](const std::string& value) {
        this->OnUpdate(value);
    };
    sptr<SettingObserver> settingObserver = settingHelper.CreateObserver(CONFIG_WHITELIST, updateFunc);
    if (settingObserver == nullptr) {
        MMI_HILOGE("CreateObserver failed");
        return RET_ERR;
    }
    if (int32_t ret = settingHelper.RegisterObserver(settingObserver, SETTING_URI_PROXY) != ERR_OK) {
        MMI_HILOGE("RegisterObserver failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
 
void WhitelistDataShareAccessor::OnUpdate(const std::string &whitelist)
{
    MMI_HILOGI("Whitelist updated, %{public}s", whitelist.c_str());
    UpdateWhitelist(Split(whitelist));
}
 
std::vector<std::string> WhitelistDataShareAccessor::Split(const std::string& str, char delimiter)
{
    std::vector<std::string> tokens;
    if (str.empty()) {
        MMI_HILOGE("Str is empty");
        return tokens;
    }
    std::istringstream iss(str);
    std::string token;
    while (std::getline(iss, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}
 
void WhitelistDataShareAccessor::UpdateWhitelist(const std::vector<std::string> &whitelist)
{
    CALL_INFO_TRACE;
    std::unique_lock<std::shared_mutex> lock(mtx_);
    whitelist_ = std::unordered_set<std::string>(whitelist.begin(), whitelist.end());
}
} // namespace MMI
} // namespace OHOS
 