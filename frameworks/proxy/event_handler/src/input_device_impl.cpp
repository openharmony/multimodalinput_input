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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceImpl"}; // namepace
}
InputDeviceImpl& InputDeviceImpl::GetInstance()
{
    static InputDeviceImpl instance;
    return instance;
}

void InputDeviceImpl::GetInputDeviceIdsAsync(int32_t userData,
    std::function<void(int32_t, std::vector<int32_t>)> callback)
{
    MMI_LOGD("begin");
    inputDevciceIds_[userData] = callback;
    MMIEventHdl.GetDeviceIds(userData);
    MMI_LOGD("end");
}

void InputDeviceImpl::GetInputDeviceAsync(int32_t userData, int32_t deviceId,
    std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)> callback)
{
    MMI_LOGD("begin");
    inputDevcices_[userData] = callback;
    MMIEventHdl.GetDevice(userData, deviceId);
    MMI_LOGD("end");
}

void InputDeviceImpl::OnInputDevice(int32_t userData, int32_t id, std::string name, int32_t deviceType)
{
    MMI_LOGD("begin");
    auto iter = inputDevcices_.find(userData);
    if (iter == inputDevcices_.end()) {
        MMI_LOGE("failed to find the callback function");
        return;
    }
    auto inputDeviceInfo = std::make_shared<InputDeviceInfo>(id, name, deviceType);
    iter->second(userData, inputDeviceInfo);
    MMI_LOGD("end");
}

void InputDeviceImpl::OnInputDeviceIds(int32_t userData, std::vector<int32_t> ids)
{
    MMI_LOGD("begin");
    auto iter = inputDevciceIds_.find(userData);
    if (iter == inputDevciceIds_.end()) {
        MMI_LOGE("failed to find the callback function");
        return;
    }
    iter->second(userData, ids);
    MMI_LOGD("end");
}
} // namespace MMI
} // namespace OHOS