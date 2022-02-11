/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceImpl"};
}
InputDeviceImpl& InputDeviceImpl::GetInstance()
{
    static InputDeviceImpl instance;
    return instance;
}

InputDeviceImpl::InputDeviceImpl() {}

InputDeviceImpl::~InputDeviceImpl() {}

void InputDeviceImpl::GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback)
{
    MMI_LOGI("begin");
    std::lock_guard<std::mutex> guard(mtx_);
    inputDevciceIds_[idsUD_] = callback;
    MMIEventHdl.GetDeviceIds(idsUD_);
    if (idsUD_ > INT_MAX) {
        MMI_LOGE("the idsUD_ exceeded the upper limit");
        idsUD_ = 0;
        return;
    }
    idsUD_++;
    MMI_LOGI("end");
}

void InputDeviceImpl::GetInputDeviceAsync(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDeviceInfo>)> callback)
{
    MMI_LOGI("begin");
    std::lock_guard<std::mutex> guard(mtx_);
    inputDevcices_[inputDeviceUD_] = callback;
    MMIEventHdl.GetDevice(inputDeviceUD_, deviceId);
    if (inputDeviceUD_ > INT_MAX) {
        MMI_LOGE("the inputDeviceUD_ exceeded the upper limit");
        inputDeviceUD_ = 0;
        return;
    }
    inputDeviceUD_++;
    MMI_LOGI("end");
}

void InputDeviceImpl::OnInputDevice(int32_t userData, int32_t id, std::string name, int32_t deviceType)
{
    MMI_LOGI("begin");
    auto inputDeviceInfo = std::make_shared<InputDeviceInfo>();
    inputDeviceInfo->id = id;
    inputDeviceInfo->name = name;
    inputDeviceInfo->devcieType = deviceType;

    for (auto it = inputDevcices_.begin(); it != inputDevcices_.end(); it++) {
        if (it->first == userData) {
            it->second(inputDeviceInfo);
        }
    }
    MMI_LOGI("end");
}

void InputDeviceImpl::OnInputDeviceIds(int32_t userData, std::vector<int32_t> ids)
{
    MMI_LOGI("begin");
    for (auto it = inputDevciceIds_.begin(); it != inputDevciceIds_.end(); it++) {
        if (it->first == userData) {
            it->second(ids);
        }
    }
    MMI_LOGI("end");
}
}
}