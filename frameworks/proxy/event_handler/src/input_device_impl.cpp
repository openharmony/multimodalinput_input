/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "input_device_impl.h"

#include "multimodal_input_connect_manager.h"
#include "bytrace_adapter.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceImpl"

namespace OHOS {
namespace MMI {
namespace {
constexpr std::string_view INPUT_DEV_CHANGE_ADD_DEV { "add" };
constexpr std::string_view INPUT_DEV_CHANGE_REMOVE_DEV { "remove" };
}

InputDeviceImpl& InputDeviceImpl::GetInstance()
{
    static InputDeviceImpl instance;
    return instance;
}

int32_t InputDeviceImpl::RegisterDevListener(const std::string &type, InputDevListenerPtr listener)
{
    CHKPR(listener, RET_ERR);
    MMI_HILOGI("Register listener of change of input devices");

    bool needStartServer = false;
    {
        std::lock_guard<std::mutex> guard(devListenerMutex_);
        auto iter = devListener_.find(type);
        if (iter == devListener_.end()) {
            MMI_HILOGE("Type of listener (%{public}s) is not supported", type.c_str());
            return RET_ERR;
        }

        auto &listeners = iter->second;
        bool isNew = std::all_of(listeners.cbegin(), listeners.cend(),
            [listener](InputDevListenerPtr tListener) {
                return (tListener != listener);
            });
        if (isNew) {
            listeners.push_back(listener);
            needStartServer = listeners.size();
        }
    }

    if (needStartServer) {
        auto ret = StartListeningToServer();
        if (ret != RET_OK) {
            MMI_HILOGE("StartListeningToServer fail, error:%{public}d", ret);
            std::lock_guard<std::mutex> guard(devListenerMutex_);
            auto iter = devListener_.find(type);
            if (iter != devListener_.end()) {
                iter->second.remove(listener);
            }
            return ret;
        }
    }

    MMI_HILOGI("Succeed to register listener of change of input devices");
    return RET_OK;
}

int32_t InputDeviceImpl::UnregisterDevListener(const std::string &type, InputDevListenerPtr listener)
{
    bool needStopServer = false;
    {
        std::lock_guard<std::mutex> guard(devListenerMutex_);
        auto iter = devListener_.find(type);
        if (iter == devListener_.end()) {
            MMI_HILOGE("Type of listener (%{public}s) is not supported", type.c_str());
            return RET_ERR;
        }

        auto &listeners = iter->second;
        if (listener == nullptr) {
            MMI_HILOGI("Unregister all listeners of change of input devices");
            needStopServer = !listeners.empty();
            listeners.clear();
        } else {
            MMI_HILOGI("Unregister listener of change of input devices");
            size_t oldSize = listeners.size();
            listeners.remove_if([listener](const auto &item) {
                return (item == listener);
            });
            needStopServer = (oldSize > 0) && listeners.empty();
        }
    }

    if (needStopServer) {
        StopListeningToServer();
    }
    return RET_OK;
}

void InputDeviceImpl::OnDevListener(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Change(%{public}s) of input device(%{public}d)", type.c_str(), deviceId);

    std::vector<InputDevListenerPtr> listenersToNotify;
    {
        std::lock_guard<std::mutex> guard(devListenerMutex_);
        auto iter = devListener_.find(CHANGED_TYPE);
        if (iter == devListener_.end()) {
            MMI_HILOGE("Find change failed");
            return;
        }
        listenersToNotify.assign(iter->second.begin(), iter->second.end());
    }

    BytraceAdapter::StartDevListener(type, deviceId);

    for (const auto &item : listenersToNotify) {
        if (type == INPUT_DEV_CHANGE_ADD_DEV) {
            item->OnDeviceAdded(deviceId, type);
        } else if (type == INPUT_DEV_CHANGE_REMOVE_DEV) {
            item->OnDeviceRemoved(deviceId, type);
        }
    }
    BytraceAdapter::StopDevListener();
}

int32_t InputDeviceImpl::GetInputDeviceIds(FunInputDevIds callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    std::vector<int32_t> ids;
    if (MULTIMODAL_INPUT_CONNECT_MGR->GetDeviceIds(ids) != RET_OK) {
        MMI_HILOGE("GetInputDeviceIds failed");
        return RET_ERR;
    }
    callback(ids);
    return RET_OK;
}

int32_t InputDeviceImpl::GetInputDevice(int32_t deviceId, FunInputDevInfo callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    if (MULTIMODAL_INPUT_CONNECT_MGR->GetDevice(deviceId, inputDevice) != RET_OK) {
        MMI_HILOGE("GetDevice failed");
        return RET_ERR;
    }
    callback(inputDevice);
    return RET_OK;
}

int32_t InputDeviceImpl::SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes, FunInputDevKeys callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    std::vector<bool> keystroke;
    if (MULTIMODAL_INPUT_CONNECT_MGR->SupportKeys(deviceId, keyCodes, keystroke) != RET_OK) {
        MMI_HILOGE("SupportKeys failed");
        return RET_ERR;
    }
    callback(keystroke);
    return RET_OK;
}

int32_t InputDeviceImpl::GetKeyboardType(int32_t deviceId, FunKeyboardTypes callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    int32_t keyboardType = 0;
    if (MULTIMODAL_INPUT_CONNECT_MGR->GetKeyboardType(deviceId, keyboardType) != RET_OK) {
        MMI_HILOGE("GetKeyboardType failed");
        return RET_ERR;
    }
    callback(keyboardType);
    return RET_OK;
}

int32_t InputDeviceImpl::SetKeyboardRepeatDelay(int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (MULTIMODAL_INPUT_CONNECT_MGR->SetKeyboardRepeatDelay(delay) != RET_OK) {
        MMI_HILOGE("SetKeyboardRepeatDelay failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputDeviceImpl::SetKeyboardRepeatRate(int32_t rate)
{
    CALL_DEBUG_ENTER;
    if (MULTIMODAL_INPUT_CONNECT_MGR->SetKeyboardRepeatRate(rate) != RET_OK) {
        MMI_HILOGE("SetKeyboardRepeatRate failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputDeviceImpl::GetKeyboardRepeatDelay(std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    int32_t repeatDelay = 0;
    if (MULTIMODAL_INPUT_CONNECT_MGR->GetKeyboardRepeatDelay(repeatDelay) != RET_OK) {
        MMI_HILOGE("GetKeyboardRepeatDelay failed");
        return RET_ERR;
    }
    callback(repeatDelay);
    return RET_OK;
}

int32_t InputDeviceImpl::GetKeyboardRepeatRate(std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    int32_t repeatRate = 0;
    if (MULTIMODAL_INPUT_CONNECT_MGR->GetKeyboardRepeatRate(repeatRate) != RET_OK) {
        MMI_HILOGE("GetKeyboardRepeatRate failed");
        return RET_ERR;
    }
    callback(repeatRate);
    return RET_OK;
}

int32_t InputDeviceImpl::GetUserData()
{
    return userData_;
}

int32_t InputDeviceImpl::RegisterInputdevice(int32_t deviceId, bool enable, std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, RET_ERR);
    int32_t _id;
    {
        std::lock_guard<std::mutex> guard(inputDeviceMutex_);
        _id = operationIndex_++;
        inputdeviceList_[_id] = callback;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetInputDeviceEnabled(deviceId, enable, _id);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to register");
        return ret;
    }
    return RET_OK;
}

void InputDeviceImpl::OnSetInputDeviceAck(int32_t index, int32_t result)
{
    CALL_DEBUG_ENTER;
    std::function<void(int32_t)> callback;
    {
        std::lock_guard<std::mutex> guard(inputDeviceMutex_);
        auto iter = inputdeviceList_.find(index);
        if (iter == inputdeviceList_.end()) {
            MMI_HILOGE("Find index failed");
            return;
        }
        callback = std::move(iter->second);
        inputdeviceList_.erase(iter);
    }
    callback(result);
}

void InputDeviceImpl::OnConnected()
{
    bool shouldStartServer = false;
    {
        std::lock_guardstd::mutex guard(devListenerMutex_);
        auto iter = devListener_.find(CHANGED_TYPE);
        shouldStartServer = (iter != devListener_.end()) && !iter->second.empty();
    }

    if (!shouldStartServer) {
        return;
    }

    auto ret = StartListeningToServer();
    if (ret != RET_OK) {
        MMI_HILOGE("StartListeningToServer fail, error:%{public}d", ret);
    }
}

void InputDeviceImpl::OnDisconnected()
{
    MMI_HILOGI("Disconnected from server");
    isListeningProcess_.store(false);
}

int32_t InputDeviceImpl::StartListeningToServer()
{
    if (isListeningProcess_.load()) {
        return RET_OK;
    }
    MMI_HILOGI("Start monitoring changes of input devices");
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->RegisterDevListener();
    if (ret != RET_OK) {
        MMI_HILOGE("RegisterDevListener to server fail, error:%{public}d", ret);
        return ret;
    }
    isListeningProcess_.store(true);
    return RET_OK;
}

void InputDeviceImpl::StopListeningToServer()
{
    if (!isListeningProcess_.load()) {
        return;
    }
    MMI_HILOGI("Stop monitoring changes of input devices");
    auto ret = MULTIMODAL_INPUT_CONNECT_MGR->UnregisterDevListener();
    if (ret != RET_OK) {
        MMI_HILOGE("UnregisterDevListener from server fail, error:%{public}d", ret);
    }
    isListeningProcess_.store(false);
}
} // namespace MMI
} // namespace OHOS
