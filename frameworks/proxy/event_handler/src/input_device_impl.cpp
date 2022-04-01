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
    InputDeviceData data;
    data.ids = callback;
    inputDevices_[userData] = data;
    MMIEventHdl.GetDeviceIds(userData);
}

void InputDeviceImpl::GetInputDeviceAsync(int32_t userData, int32_t deviceId,
    std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)> callback)
{
    CALL_LOG_ENTER;
    InputDeviceData data;
    data.inputDevice = callback;
    inputDevices_[userData] = data;
    MMIEventHdl.GetDevice(userData, deviceId);
}

void InputDeviceImpl::GetKeystrokeAbility(int32_t userData, int32_t deviceId, std::vector<int32_t> keyCodes,
    std::function<void(int32_t, std::vector<int32_t>)> callback)
{
    CALL_LOG_ENTER;
    InputDeviceData data;
    data.keys = callback;
    inputDevices_[userData] = data;
    MMIEventHdl.GetKeystrokeAbility(userData, deviceId, keyCodes);
}

void InputDeviceImpl::OnInputDevice(int32_t userData, int32_t id, std::string name, int32_t deviceType)
{
    CALL_LOG_ENTER;
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    auto inputDeviceInfo = std::make_shared<InputDeviceInfo>(id, name, deviceType);
    CHKPV(inputDeviceInfo);
    iter->second.inputDevice(userData, inputDeviceInfo);
}

void InputDeviceImpl::OnInputDeviceIds(int32_t userData, std::vector<int32_t> ids)
{
    CALL_LOG_ENTER;
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    iter->second.ids(userData, ids);
}

void InputDeviceImpl::OnKeystrokeAbility(int32_t userData, std::vector<int32_t> keystrokeAbility)
{
    CALL_LOG_ENTER;
    auto iter = inputDevices_.find(userData);
    if (iter == inputDevices_.end()) {
        MMI_HILOGE("failed to find the callback function");
        return;
    }
    iter->second.keys(userData, keystrokeAbility);
}
} // namespace MMI
} // namespace OHOS