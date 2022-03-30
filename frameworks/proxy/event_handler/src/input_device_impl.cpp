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

#include "mmi_client.h"
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

void InputDeviceImpl::GetInputDeviceIdsAsync(int32_t userData,
    std::function<void(int32_t, std::vector<int32_t>)> callback)
{
    CALL_LOG_ENTER;
    auto eventHandler = AppExecFwk::EventHandler::Current();
    if (eventHandler == nullptr) {
        eventHandler = InputMgrImp->GetEventHandler();
    }
    inputDevciceIds_[userData] = std::make_pair(eventHandler, callback);
    MMIEventHdl.GetDeviceIds(userData);
}

void InputDeviceImpl::GetInputDeviceAsync(int32_t userData, int32_t deviceId,
    std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)> callback)
{
    CALL_LOG_ENTER;
    auto eventHandler = AppExecFwk::EventHandler::Current();
    if (eventHandler == nullptr) {
        eventHandler = InputMgrImp->GetEventHandler();
    }
    inputDevcices_[userData] = std::make_pair(eventHandler, callback);
    MMIEventHdl.GetDevice(userData, deviceId);
}

void InputDeviceImpl::OnInputDevice(int32_t userData, int32_t id, std::string name, int32_t deviceType)
{
    CALL_LOG_ENTER;
    auto callMsgHandler = [this, userData, id, name, deviceType] () {
        CHK_PIDANDTID(callMsgHandler);
        std::lock_guard<std::mutex> guard(mtx_);
        auto devInfo = GetDeviceInfo(userData);
        if (devInfo == nullptr) {
            MMI_HILOGE("failed to find the callback function");
            return;
        }
        auto devData = std::make_shared<InputDeviceInfo>(id, name, deviceType);
        CHKPV(devData);
        devInfo->second(userData, devData);
    };

    std::lock_guard<std::mutex> guard(mtx_);
    auto devInfo = GetDeviceInfo(userData);
    if (devInfo == nullptr) {
        devInfo("failed to find the callback function");
        return;
    }
    auto eventHandler = devInfo->eventHandler;
    if (eventHandler == nullptr) {
        MMI_HILOGE("event handler is nullptr");
        return;
    }
    if (!eventHandler->PostHighPriorityTask(callMsgHandler)) {
        MMI_HILOGE("post task failed");
    }
}

void InputDeviceImpl::OnInputDeviceIds(int32_t userData, std::vector<int32_t> ids)
{
    CALL_LOG_ENTER;
    auto callMsgHandler = [this, userData, ids] () {
        CHK_PIDANDTID(callMsgHandler);
        std::lock_guard<std::mutex> guard(mtx_);
        auto devIds = GetDeviceIds(userData);
        if (devIds == nullptr) {
            MMI_HILOGE("failed to find the callback function");
            return;
        }
        devIds->second(userData, ids);
    };

    std::lock_guard<std::mutex> guard(mtx_);
    auto devIds = GetDeviceIds(userData);
    if (devIds == nullptr) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    auto eventHandler = devIds->eventHandler;
    if (eventHandler == nullptr) {
        MMI_HILOGE("event handler is nullptr");
        return;
    }
    if (!eventHandler->PostHighPriorityTask(callMsgHandler)) {
        MMI_HILOGE("post task failed");
    }
}

const DevInfo* InputDeviceImpl::GetDeviceInfo(int32_t id) const
{
    auto iter = inputDevcices_.find(userData);
    if (iter == inputDevcices_.end()) {
        return nullptr;
    }
    return &iter->second;
}

const DevIds* InputDeviceImpl::GetDeviceIds(int32_t id) const
{
    auto iter = inputDevciceIds_.find(id);
    if (iter == inputDevciceIds_.end()) {
        return nullptr;
    }
    return &iter->second;
}
} // namespace MMI
} // namespace OHOS