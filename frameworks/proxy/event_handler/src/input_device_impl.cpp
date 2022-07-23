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
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceImpl"};
const std::string CHANGED_TYPE = "change";
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
        if (item.second == listener) {
            MMI_HILOGW("The listener already exists");
            return RET_ERR;
        }
    }
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPR(eventHandler, RET_ERR);
    auto monitor = std::make_pair(eventHandler, listener);
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
        if (it->second == listener) {
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

void InputDeviceImpl::OnDevListenerTask(const DevListener &devMonitor, const std::string &type, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Report device change task, event type:%{public}s", type.c_str());
    if (type == "add") {
        devMonitor.second->OnDeviceAdded(deviceId, type);
        return;
    }
    devMonitor.second->OnDeviceRemoved(deviceId, type);
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
        if (!MMIEventHandler::PostTask(item.first,
            std::bind(&InputDeviceImpl::OnDevListenerTask, this, item, type, deviceId))) {
            MMI_HILOGE("Post task failed");
        }
    }
}

int32_t InputDeviceImpl::GetInputDeviceIdsAsync(FunInputDevIds callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPR(eventHandler, RET_ERR);
    InputDeviceData data;
    data.ids = std::make_pair(eventHandler, callback);
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
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPR(eventHandler, RET_ERR);
    InputDeviceData data;
    data.inputDevice = std::make_pair(eventHandler, callback);
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
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPR(eventHandler, RET_ERR);
    InputDeviceData data;
    data.keys = std::make_pair(eventHandler, callback);
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
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPR(eventHandler, RET_ERR);
    InputDeviceData data;
    data.kbTypes = std::make_pair(eventHandler, callback);
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("UserData exceeds the maximum");
        return RET_ERR;
    }
    inputDevices_[userData_] = data;
    return MultimodalInputConnMgr->GetKeyboardType(userData_++, deviceId);
}

void InputDeviceImpl::OnInputDeviceTask(const DevInfo &devInfo, int32_t userData, std::shared_ptr<InputDevice> devData)
{
    CHK_PID_AND_TID();
    CHKPV(devData);
    devInfo.second(devData);
    MMI_HILOGD("Report device info task, userData:%{public}d name:%{public}s",
        userData, devData->GetName().c_str());
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
    if (!MMIEventHandler::PostTask(devInfo->first,
        std::bind(&InputDeviceImpl::OnInputDeviceTask, this, *devInfo, userData, devData))) {
        MMI_HILOGE("Post task failed");
    }
    MMI_HILOGD("Report device info, userData:%{public}d name:%{public}s type:%{public}d",
        userData, devData->GetName().c_str(), devData->GetType());
}

void InputDeviceImpl::OnInputDeviceIdsTask(const DevIds &devIds, int32_t userData, std::vector<int32_t> &ids)
{
    CHK_PID_AND_TID();
    devIds.second(ids);
    MMI_HILOGD("Report all device, userData:%{public}d devices:(%{public}s)",
        userData, IdsListToString(ids).c_str());
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
    if (!MMIEventHandler::PostTask(devIds->first,
        std::bind(&InputDeviceImpl::OnInputDeviceIdsTask, this, *devIds, userData, ids))) {
        MMI_HILOGE("Post task failed");
    }
    MMI_HILOGD("Report all device, userData:%{public}d device:(%{public}s)",
        userData, IdsListToString(ids).c_str());
}

void InputDeviceImpl::OnSupportKeysTask(const DevKeys &devKeys, int32_t userData, std::vector<bool> &supportRet)
{
    CHK_PID_AND_TID();
    devKeys.second(supportRet);
}

void InputDeviceImpl::OnSupportKeys(int32_t userData, const std::vector<bool> &keystrokeAbility)
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
    if (!MMIEventHandler::PostTask(devKeys->first,
        std::bind(&InputDeviceImpl::OnSupportKeysTask, this, *devKeys, userData, keystrokeAbility))) {
        MMI_HILOGE("Post task failed");
    }
}

void InputDeviceImpl::OnKeyboardTypeTask(const DevKeyboardTypes &kbTypes, int32_t userData, int32_t keyboardType)
{
    CHK_PID_AND_TID();
    kbTypes.second(keyboardType);
    MMI_HILOGD("Keyboard type event callback userData:%{public}d keyboardType:(%{public}d)",
        userData, keyboardType);
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
    if (!MMIEventHandler::PostTask(devKbTypes->first,
        std::bind(&InputDeviceImpl::OnKeyboardTypeTask, this, *devKbTypes, userData, keyboardType))) {
        MMI_HILOGE("Post task failed");
    }
    MMI_HILOGD("Keyboard type event userData:%{public}d keyboardType:%{public}d",
        userData, keyboardType);
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

const InputDeviceImpl::DevKeyboardTypes* InputDeviceImpl::GetKeyboardTypes(int32_t userData) const
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
    CHKPP(devData);
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
