/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "device_profile_adapter.h"

#include <algorithm>
#include <mutex>

#include "nlohmann/json.hpp"

#include "distributed_device_profile_client.h"
#include "service_characteristic_profile.h"
#include "sync_options.h"

namespace OHOS {
namespace MMI {
using namespace OHOS::DeviceProfile;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "DeviceProfileAdapter" };
const std::string SERVICE_ID = "InputDeviceCooperation";
const std::string SERVICE_TYPE = "InputDeviceCooperation";
const std::string CHARACTERISTICS_NAME = "CurrentState";
} // namespace

DeviceProfileAdapter::DeviceProfileAdapter() {}

DeviceProfileAdapter::~DeviceProfileAdapter()
{
    std::lock_guard<std::mutex> guard(adapterLock_);
    profileEventCallbacks_.clear();
    callbacks_.clear();
}

int32_t DeviceProfileAdapter::UpdateCrossingSwitchState(bool state, const std::vector<std::string> &deviceIds)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json data;
    data[CHARACTERISTICS_NAME] = state;
    profile.SetCharacteristicProfileJson(data.dump());

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    if (ret != 0) {
        MMI_HILOGE("Put device profile failed, ret:%{public}d", ret);
        return ret;
    }
    SyncOptions syncOptions;
    std::for_each(deviceIds.begin(), deviceIds.end(),
                  [&syncOptions](auto &deviceId) { syncOptions.AddDevice(deviceId); });
    auto syncCallback = std::make_shared<DeviceProfileAdapter::ProfileEventCallbackImpl>();
    ret =
        DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOptions, syncCallback);
    if (ret != 0) {
        MMI_HILOGE("Sync device profile failed");
    }
    return ret;
}

int32_t DeviceProfileAdapter::UpdateCrossingSwitchState(bool state)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json data;
    data[CHARACTERISTICS_NAME] = state;
    profile.SetCharacteristicProfileJson(data.dump());
    return DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
}

bool DeviceProfileAdapter::GetCrossingSwitchState(const std::string &deviceId)
{
    ServiceCharacteristicProfile profile;
    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(deviceId, SERVICE_ID, profile);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    nlohmann::json jsonObject = nlohmann::json::parse(jsonData, nullptr, false);
    if (jsonObject.is_discarded()) {
        MMI_HILOGE("JsonData is discarded");
        return false;
    }
    return jsonObject[CHARACTERISTICS_NAME].get<bool>();
}

int32_t DeviceProfileAdapter::RegisterCrossingStateListener(const std::string &deviceId, DPCallback callback)
{
    CHKPR(callback, RET_ERR);
    if (deviceId.empty()) {
        MMI_HILOGE("DeviceId is nullptr");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(adapterLock_);
    auto callbackIter = callbacks_.find(deviceId);
    if (callbackIter != callbacks_.end()) {
        callbackIter->second = callback;
        MMI_HILOGW("Callback is updated");
        return RET_OK;
    }
    callbacks_[deviceId] = callback;
    MMI_HILOGI("Register crossing state listener success");
    if (RegisterProfileListener(deviceId) != RET_OK) {
        MMI_HILOGE("Register profile listener failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceProfileAdapter::UnregisterCrossingStateListener(const std::string &deviceId)
{
    if (deviceId.empty()) {
        MMI_HILOGE("DeviceId is empty");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(adapterLock_);
    auto it = profileEventCallbacks_.find(deviceId);
    if (it != profileEventCallbacks_.end()) {
        std::list<ProfileEvent> profileEvents;
        profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
        std::list<ProfileEvent> failedEvents;
        DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents,
            it->second, failedEvents);
        profileEventCallbacks_.erase(it);
    }
    auto callbackIter = callbacks_.find(deviceId);
    if (callbackIter == callbacks_.end()) {
        MMI_HILOGW("This device has no callback");
        return RET_OK;
    }
    callbacks_.erase(callbackIter);
    return RET_OK;
}

int32_t DeviceProfileAdapter::RegisterProfileListener(const std::string &deviceId)
{
    std::list<std::string> serviceIdList;
    serviceIdList.emplace_back(SERVICE_ID);
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIdList;
    SubscribeInfo changeEventInfo;
    changeEventInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    changeEventInfo.extraInfo = std::move(extraInfo);
    std::list<SubscribeInfo> subscribeInfos;
    subscribeInfos.emplace_back(changeEventInfo);
    SubscribeInfo syncEventInfo;
    syncEventInfo.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    subscribeInfos.emplace_back(syncEventInfo);
    std::list<ProfileEvent> failedEvents;
    auto it = profileEventCallbacks_.find(deviceId);
    if (it == profileEventCallbacks_.end() || it->second == nullptr) {
        profileEventCallbacks_[deviceId] = std::make_shared<DeviceProfileAdapter::ProfileEventCallbackImpl>();
    }
    return DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(
        subscribeInfos, profileEventCallbacks_[deviceId], failedEvents);
}

void DeviceProfileAdapter::OnProfileChanged(const std::string &deviceId)
{
    std::lock_guard<std::mutex> guard(adapterLock_);
    auto it = callbacks_.find(deviceId);
    if (it == callbacks_.end()) {
        MMI_HILOGW("The device has no callback");
        return;
    }
    if (it->second != nullptr) {
        auto state = GetCrossingSwitchState(deviceId);
        it->second(deviceId, state);
    } else {
        callbacks_.erase(it);
    }
}

void DeviceProfileAdapter::ProfileEventCallbackImpl::OnProfileChanged(
    const ProfileChangeNotification &changeNotification)
{
    CALL_INFO_TRACE;
    std::string deviceId = changeNotification.GetDeviceId();
    DProfileAdapter->OnProfileChanged(deviceId);
}

void DeviceProfileAdapter::ProfileEventCallbackImpl::OnSyncCompleted(const DeviceProfile::SyncResult &syncResults)
{
    std::for_each(syncResults.begin(), syncResults.end(), [](const auto &syncResult) {
        MMI_HILOGD("Sync result:%{public}d", syncResult.second);
    });
}
} // namespace MMI
} // namespace OHOS
