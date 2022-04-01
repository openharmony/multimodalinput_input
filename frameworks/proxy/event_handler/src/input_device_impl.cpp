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

void InputDeviceImpl::OnInputDeviceTask(int32_t userData, int32_t id, std::string name, int32_t deviceType)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto devInfo = GetDeviceInfo(userData);
    if (devInfo == nullptr) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    auto devData = std::make_shared<InputDeviceInfo>(id, name, deviceType);
    CHKPV(devData);
    devInfo->second(userData, devData);
    MMI_HILOGD("device info event callback userData:%{public}d id:%{public}d name:%{public}s type:%{public}d",
        userData, id, name.c_str(), deviceType);
}

void InputDeviceImpl::OnInputDevice(int32_t userData, int32_t id, const std::string &name, int32_t deviceType)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto devInfo = GetDeviceInfo(userData);
    if (devInfo == nullptr) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    if (!MMIEventHandler::PostTask(devInfo->first,
        std::bind(&InputDeviceImpl::OnInputDeviceTask, this, userData, id, name, deviceType))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("device info event userData:%{public}d id:%{public}d name:%{public}s type:%{public}d",
        userData, id, name.c_str(), deviceType);
}

void InputDeviceImpl::OnInputDeviceIdsTask(int32_t userData, std::vector<int32_t> ids)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto devIds = GetDeviceIds(userData);
    if (devIds == nullptr) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    devIds->second(userData, ids);
    MMI_HILOGD("device ids event callback userData:%{public}d ids:(%{public}s)",
        userData, IdsListToString(ids).c_str());
}

void InputDeviceImpl::OnInputDeviceIds(int32_t userData, const std::vector<int32_t> &ids)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto devIds = GetDeviceIds(userData);
    if (devIds == nullptr) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    if (!MMIEventHandler::PostTask(devIds->first,
        std::bind(&InputDeviceImpl::OnInputDeviceIdsTask, this, userData, ids))) {
        MMI_HILOGE("post task failed");
    }
    MMI_HILOGD("device ids event userData:%{public}d ids:(%{public}s)", userData, IdsListToString(ids).c_str());
}

const InputDeviceImpl::DevInfo* InputDeviceImpl::GetDeviceInfo(int32_t userData) const
{
    auto iter = inputDevcices_.find(userData);
    if (iter == inputDevcices_.end()) {
        return nullptr;
    }
    return &iter->second;
}

const InputDeviceImpl::DevIds* InputDeviceImpl::GetDeviceIds(int32_t userData) const
{
    auto iter = inputDevciceIds_.find(userData);
    if (iter == inputDevciceIds_.end()) {
        return nullptr;
    }
    return &iter->second;
}
} // namespace MMI
} // namespace OHOS