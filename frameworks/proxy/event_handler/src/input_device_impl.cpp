/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input_device_impl.h"

#include "input_manager_impl.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceImpl"};
} // namespace

InputDeviceImpl& InputDeviceImpl::GetInstance()
{
    static InputDeviceImpl instance;
    return instance;
}

void InputDeviceImpl::RegisterInputDeviceMonitor(std::function<void(std::string, int32_t)> listening)
{
    CALL_LOG_ENTER;
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPV(eventHandler);
    auto listen = std::make_pair(eventHandler, listening);
    devMonitor_ = listen;
    MMIEventHdl.RegisterInputDeviceMonitor();
}

void InputDeviceImpl::UnRegisterInputDeviceMonitor()
{
    MMIEventHdl.UnRegisterInputDeviceMonitor();
}

void InputDeviceImpl::OnDevMonitorTask(DevMonitor devMonitor, std::string type, int32_t deviceId)
{
    CALL_LOG_ENTER;
    devMonitor.second(type, deviceId);
    MMI_HILOGD("device info event callback event type:%{public}s deviceId:%{public}d", type.c_str(), deviceId);
}

void InputDeviceImpl::OnDevMonitor(std::string type, int32_t deviceId)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHandler::PostTask(devMonitor_.first,
        std::bind(&InputDeviceImpl::OnDevMonitorTask, this, devMonitor_, type, deviceId))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("device info event callback event type:%{public}s deviceId:%{public}d", type.c_str(), deviceId);
}

void InputDeviceImpl::GetInputDeviceIdsAsync(int32_t userData,
    std::function<void(int32_t, std::vector<int32_t>)> callback)
{
    CALL_LOG_ENTER;
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPV(eventHandler);
    InputDeviceData data;
    data.ids = std::make_pair(eventHandler, callback);
    inputDevices_[userData] = data;
    MMIEventHdl.GetDeviceIds(userData);
}

void InputDeviceImpl::GetInputDeviceAsync(int32_t userData, int32_t deviceId,
    std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)> callback)
{
    CALL_LOG_ENTER;
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPV(eventHandler);
    InputDeviceData data;
    data.inputDevice = std::make_pair(eventHandler, callback);
    inputDevices_[userData] = data;
    MMIEventHdl.GetDevice(userData, deviceId);
}

void InputDeviceImpl::GetKeystrokeAbility(int32_t userData, int32_t deviceId, std::vector<int32_t> keyCodes,
    std::function<void(int32_t, std::vector<int32_t>)> callback)
{
    CALL_LOG_ENTER;
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPV(eventHandler);
    InputDeviceData data;
    data.keys = std::make_pair(eventHandler, callback);
    inputDevices_[userData] = data;
    MMIEventHdl.GetKeystrokeAbility(userData, deviceId, keyCodes);
}

void InputDeviceImpl::OnInputDeviceTask(InputDeviceImpl::DevInfo devInfo, int32_t userData,
    int32_t id, std::string name, int32_t deviceType)
{
    CHK_PIDANDTID();
    auto devData = std::make_shared<InputDeviceInfo>(id, name, deviceType);
    CHKPV(devData);
    devInfo.second(userData, devData);
    MMI_HILOGD("device info event callback userData:%{public}d id:%{public}d name:%{public}s type:%{public}d",
        userData, id, name.c_str(), deviceType);
}

void InputDeviceImpl::OnInputDevice(int32_t userData, int32_t id, const std::string &name, int32_t deviceType)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto devInfo = GetDeviceInfo(userData);
    CHKPV(devInfo);
    if (!MMIEventHandler::PostTask(devInfo->first,
        std::bind(&InputDeviceImpl::OnInputDeviceTask, this, *devInfo, userData, id, name, deviceType))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("device info event userData:%{public}d id:%{public}d name:%{public}s type:%{public}d",
        userData, id, name.c_str(), deviceType);
}

void InputDeviceImpl::OnInputDeviceIdsTask(InputDeviceImpl::DevIds devIds, int32_t userData, std::vector<int32_t> ids)
{
    CHK_PIDANDTID();
    devIds.second(userData, ids);
    MMI_HILOGD("device ids event callback userData:%{public}d ids:(%{public}s)",
        userData, IdsListToString(ids).c_str());
}

void InputDeviceImpl::OnInputDeviceIds(int32_t userData, const std::vector<int32_t> &ids)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto devIds = GetDeviceIds(userData);
    CHKPV(devIds);
    if (!MMIEventHandler::PostTask(devIds->first,
        std::bind(&InputDeviceImpl::OnInputDeviceIdsTask, this, *devIds, userData, ids))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("device ids event userData:%{public}d ids:(%{public}s)", userData, IdsListToString(ids).c_str());
}

void InputDeviceImpl::OnKeystrokeAbilityTask(InputDeviceImpl::DevKeys devKeys, int32_t userData,
    std::vector<int32_t> keystrokeAbility)
{
    CHK_PIDANDTID();
    devKeys.second(userData, keystrokeAbility);
    MMI_HILOGD("device keys event callback userData:%{public}d keys:(%{public}s)",
        userData, IdsListToString(keystrokeAbility).c_str());
}

void InputDeviceImpl::OnKeystrokeAbility(int32_t userData, const std::vector<int32_t> &keystrokeAbility)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto devKeys = GetDeviceKeys(userData);
    CHKPV(devKeys);
    if (!MMIEventHandler::PostTask(devKeys->first,
        std::bind(&InputDeviceImpl::OnKeystrokeAbilityTask, this, *devKeys, userData, keystrokeAbility))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("device keys event userData:%{public}d ids:(%{public}s)",
        userData, IdsListToString(keystrokeAbility).c_str());
}

const InputDeviceImpl::DevInfo* InputDeviceImpl::GetDeviceInfo(int32_t userData) const
{
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        return nullptr;
    }
    return &iter->second.inputDevice;
}

const InputDeviceImpl::DevIds* InputDeviceImpl::GetDeviceIds(int32_t userData) const
{
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        return nullptr;
    }
    return &iter->second.ids;
}

const InputDeviceImpl::DevKeys* InputDeviceImpl::GetDeviceKeys(int32_t userData) const
{
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        return nullptr;
    }
    return &iter->second.keys;
}
} // namespace MMI
} // namespace OHOS