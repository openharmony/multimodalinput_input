/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "ability_manager_client.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AbilityManagerClientStub"

namespace OHOS {
namespace AAFwk {
std::shared_ptr<AbilityManagerClient> AbilityManagerClient::instance_ = nullptr;

Want &Want::SetElementName(const std::string &deviceId, const std::string &bundleName,
    const std::string &abilityName, const std::string &moduleName)
{
    deviceId_ = deviceId;
    bundleName_ = bundleName;
    abilityName_ = abilityName;
    moduleName_ = moduleName;

    return *this;
}

Want &Want::SetAction(const std::string &action)
{
    action_ = action;

    return *this;
}

Want &Want::SetUri(const std::string &uri)
{
    uri_ = uri;

    return *this;
}

Want &Want::SetType(const std::string &type)
{
    type_ = type;

    return *this;
}

Want &Want::AddEntity(const std::string &entity)
{
    entities_.push_back(entity);

    return *this;
}

Want &Want::SetParam(const std::string &key, const std::string &value)
{
    params_.emplace(key, value);

    return *this;
}

std::shared_ptr<AbilityManagerClient> AbilityManagerClient::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = std::make_shared<AbilityManagerClient> ();
    }
    return instance_;
}

ErrCode AbilityManagerClient::StartAbility(const Want &want, int32_t requestCode, int32_t userId)
{
    (void)want;
    (void)requestCode;
    (void)userId;

    MMI_HILOGI("StartAbility called");
    if (callback_ != nullptr) {
        callback_(want, err_);
    }

    return err_;
}

ErrCode AbilityManagerClient::StartExtensionAbility(const Want &want, sptr<IRemoteObject> callerToken)
{
    (void)want;
    (void)callerToken;

    return ERR_OK;
}

void AbilityManagerClient::SetCallback(void (*cb)(const Want &want, ErrCode err))
{
    callback_ = cb;
}

void AbilityManagerClient::SetErrCode(ErrCode err)
{
    err_ = err;
}
} // namespace AAFwk

namespace EventFwk {
    const std::string CommonEventSupport::COMMON_EVENT_SCREEN_OFF = "usual.event.SCREEN_OFF";
    const std::string CommonEventSupport::COMMON_EVENT_SCREEN_ON = "usual.event.SCREEN_ON";
    const std::string CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED = "usual.event.SCREEN_LOCKED";
    const std::string CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED = "usual.event.SCREEN_UNLOCKED";
} // namespace EventFwk
} // namespace OHOS
