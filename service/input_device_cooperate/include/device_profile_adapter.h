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

#ifndef DEVICE_PROFILE_ADAPTER_H
#define DEVICE_PROFILE_ADAPTER_H

#include <functional>
#include <memory>
#include <vector>

#include "iprofile_event_callback.h"
#include "nocopyable.h"
#include "singleton.h"

#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
class DeviceProfileAdapter final {
    DECLARE_DELAYED_SINGLETON(DeviceProfileAdapter);
    class ProfileEventCallbackImpl : public DeviceProfile::IProfileEventCallback {
    public:
        void OnSyncCompleted(const DeviceProfile::SyncResult &syncResults) override;
        void OnProfileChanged(const DeviceProfile::ProfileChangeNotification &changeNotification) override;
    };
public:
    using ProfileEventCallback = std::shared_ptr<DeviceProfile::IProfileEventCallback>;
    using DPCallback = std::function<void(const std::string &, bool)>;
    DISALLOW_COPY_AND_MOVE(DeviceProfileAdapter);

    int32_t UpdateCrossingSwitchState(bool state);
    int32_t UpdateCrossingSwitchState(bool state, const std::vector<std::string> &deviceIds);
    bool GetCrossingSwitchState(const std::string &deviceId);
    int32_t RegisterCrossingStateListener(const std::string &deviceId, DPCallback callback);
    int32_t UnregisterCrossingStateListener(const std::string &deviceId);

private:
    int32_t RegisterProfileListener(const std::string &deviceId);
    void OnProfileChanged(const std::string &deviceId);
    std::map<std::string, DeviceProfileAdapter::ProfileEventCallback> profileEventCallbacks_;
    std::mutex adapterLock_;
    std::map<std::string, DeviceProfileAdapter::DPCallback> callbacks_;
};

#define DProfileAdapter ::OHOS::DelayedSingleton<DeviceProfileAdapter>::GetInstance()
} // namespace MMI
} // namespace OHOS

#endif // DEVICE_PROFILE_ADAPTER_H