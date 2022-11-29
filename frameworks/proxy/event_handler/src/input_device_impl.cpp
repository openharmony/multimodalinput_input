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

#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "napi_constants.h"
#include "net_packet.h"

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

int32_t InputDeviceImpl::RegisterDevListener(const std::string &type, InputDevListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, RET_ERR);
    if (type != CHANGED_TYPE) {
        MMI_HILOGE("Failed to register, listener event must be \"change\"");
        return RET_ERR;
    }
    auto iter = devListener_.find(CHANGED_TYPE);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find change failed");
        return RET_ERR;
    }
    for (const auto &item : iter->second) {
        if (item == listener) {
            MMI_HILOGW("The listener already exists");
            return RET_ERR;
        }
    }
    auto monitor = listener;
    iter->second.push_back(monitor);
    if (!isListeningProcess_) {
        MMI_HILOGI("Start monitoring");
        isListeningProcess_ = true;
        return MultimodalInputConnMgr->RegisterDevListener();
    }
    return RET_OK;
}

int32_t InputDeviceImpl::UnregisterDevListener(const std::string &type, InputDevListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    if (type != CHANGED_TYPE) {
        MMI_HILOGE("Failed to cancel registration, listener event must be \"change\"");
        return RET_ERR;
    }
    auto iter = devListener_.find(CHANGED_TYPE);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find change failed");
        return RET_ERR;
    }
    if (listener == nullptr) {
        iter->second.clear();
        goto listenerLabel;
    }
    for (auto it = iter->second.begin(); it != iter->second.end(); ++it) {
        if (*it == listener) {
            iter->second.erase(it);
            goto listenerLabel;
        }
    }

listenerLabel:
    if (isListeningProcess_ && iter->second.empty()) {
        isListeningProcess_ = false;
        return MultimodalInputConnMgr->UnregisterDevListener();
    }
    return RET_OK;
}

void InputDeviceImpl::OnDevListener(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    auto iter = devListener_.find("change");
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find change failed");
        return;
    }
    for (const auto &item : iter->second) {
        MMI_HILOGI("Report device change task, event type:%{public}s", type.c_str());
        if (type == "add") {
            item->OnDeviceAdded(deviceId, type);
            continue;
        }
        item->OnDeviceRemoved(deviceId, type);
    }
}

int32_t InputDeviceImpl::GetInputDeviceIdsAsync(FunInputDevIds callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    InputDeviceData data;
    data.ids = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("userData exceeds the maximum");
        return RET_ERR;
    }
    inputDevices_[userData_] = data;
    return MultimodalInputConnMgr->GetDeviceIds(userData_++);
}

int32_t InputDeviceImpl::GetInputDeviceAsync(int32_t deviceId, FunInputDevInfo callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    InputDeviceData data;
    data.inputDevice = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("UserData exceeds the maximum");
        return RET_ERR;
    }
    inputDevices_[userData_] = data;
    return MultimodalInputConnMgr->GetDevice(userData_++, deviceId);
}

int32_t InputDeviceImpl::SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes, FunInputDevKeys callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (keyCodes.size() > MAX_SUPPORT_KEY) {
        MMI_HILOGE("Keys exceeds the max range");
        return RET_ERR;
    }
    InputDeviceData data;
    data.keys = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("UserData exceeds the maximum");
        return RET_ERR;
    }
    inputDevices_[userData_] = data;
    return MultimodalInputConnMgr->SupportKeys(userData_++, deviceId, keyCodes);
}

int32_t InputDeviceImpl::GetKeyboardType(int32_t deviceId, FunKeyboardTypes callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    InputDeviceData data;
    data.kbTypes = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("UserData exceeds the maximum");
        return RET_ERR;
    }
    inputDevices_[userData_] = data;
    return MultimodalInputConnMgr->GetKeyboardType(userData_++, deviceId);
}

void InputDeviceImpl::OnInputDevice(int32_t userData, std::shared_ptr<InputDevice> devData)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        MMI_HILOGI("Find userData failed");
        return;
    }
    auto devInfo = GetDeviceInfo(userData);
    CHKPV(devInfo);
    CHKPV(devData);
    (*devInfo)(devData);
    MMI_HILOGD("Report device info, userData:%{public}d name:%{public}s type:%{public}d",
        userData, devData->GetName().c_str(), devData->GetType());
}

void InputDeviceImpl::OnInputDeviceIds(int32_t userData, std::vector<int32_t> &ids)
{
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        MMI_HILOGI("Find userData failed");
        return;
    }
    auto devIds = GetDeviceIds(userData);
    CHKPV(devIds);
    (*devIds)(ids);
    MMI_HILOGD("Report all device, userData:%{public}d device:(%{public}s)",
        userData, IdsListToString(ids).c_str());
}

void InputDeviceImpl::OnSupportKeys(int32_t userData, std::vector<bool> &keystrokeAbility)
{
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        MMI_HILOGI("Find userData failed");
        return;
    }
    auto devKeys = GetDeviceKeys(userData);
    CHKPV(devKeys);
    (*devKeys)(keystrokeAbility);
}

void InputDeviceImpl::OnKeyboardType(int32_t userData, int32_t keyboardType)
{
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
    if (auto iter = inputDevices_.find(userData); iter == inputDevices_.end()) {
        MMI_HILOGI("Find userData failed");
        return;
    }
    auto devKbTypes = GetKeyboardTypes(userData);
    CHKPV(devKbTypes);
    (*devKbTypes)(keyboardType);
    MMI_HILOGD("Keyboard type event userData:%{public}d keyboardType:%{public}d",
        userData, keyboardType);
}

const InputDeviceImpl::FunInputDevInfo* InputDeviceImpl::GetDeviceInfo(int32_t userData) const
{
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        return nullptr;
    }
    return &iter->second.inputDevice;
}

const InputDeviceImpl::FunInputDevIds* InputDeviceImpl::GetDeviceIds(int32_t userData) const
{
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        return nullptr;
    }
    return &iter->second.ids;
}

const InputDeviceImpl::FunInputDevKeys* InputDeviceImpl::GetDeviceKeys(int32_t userData) const
{
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        return nullptr;
    }
    return &iter->second.keys;
}

const InputDeviceImpl::FunKeyboardTypes* InputDeviceImpl::GetKeyboardTypes(int32_t userData) const
{
    auto iter = inputDevices_.find(userData);
    return iter == inputDevices_.end()? nullptr : &iter->second.kbTypes;
}

int32_t InputDeviceImpl::GetUserData()
{
    return userData_;
}

std::shared_ptr<InputDevice> InputDeviceImpl::DevDataUnmarshalling(NetPacket &pkt)
{
    auto devData = std::make_shared<InputDevice>();
    int32_t deviceId;
    pkt >> deviceId;
    devData->SetId(deviceId);

    std::string name;
    pkt >> name;
    devData->SetName(name);

    int32_t deviceType;
    pkt >> deviceType;
    devData->SetType(deviceType);

    int32_t bus;
    pkt >> bus;
    devData->SetBus(bus);

    int32_t product;
    pkt >> product;
    devData->SetProduct(product);

    int32_t vendor;
    pkt >> vendor;
    devData->SetVendor(vendor);

    int32_t version;
    pkt >> version;
    devData->SetVersion(version);

    std::string phys;
    pkt >> phys;
    devData->SetPhys(phys);

    std::string uniq;
    pkt >> uniq;
    devData->SetUniq(uniq);

    size_t size;
    pkt >> size;
    std::vector<InputDevice::AxisInfo> axisInfo;
    for (size_t i = 0; i < size; ++i) {
        InputDevice::AxisInfo axis;
        int32_t type;
        pkt >> type;
        axis.SetAxisType(type);

        int32_t min;
        pkt >> min;
        axis.SetMinimum(min);

        int32_t max;
        pkt >> max;
        axis.SetMaximum(max);

        int32_t fuzz;
        pkt >> fuzz;
        axis.SetFuzz(fuzz);

        int32_t flat;
        pkt >> flat;
        axis.SetFlat(flat);

        int32_t resolution;
        pkt >> resolution;
        axis.SetResolution(resolution);
        devData->AddAxisInfo(axis);
    }
    return devData;
}
} // namespace MMI
} // namespace OHOS
