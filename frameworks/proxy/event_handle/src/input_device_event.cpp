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

#include "input_device_event.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceEvent"};
}
InputDeviceEvent& InputDeviceEvent::GetInstance()
{
    static InputDeviceEvent instance;
    return instance;
}

InputDeviceEvent::InputDeviceEvent(){}

InputDeviceEvent::~InputDeviceEvent(){}

void InputDeviceEvent::GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback)
{
    MMI_LOGI("begin");
    std::lock_guard<std::mutex> guard(lk_);
    idsRequests_.insert(std::pair<int32_t,
        std::function<void(std::vector<int32_t>)>>(idsTaskId_, callback));
    MMIEventHdl.GetDeviceIds(idsTaskId_);
    idsTaskId_++;
    MMI_LOGI("end");
}

void InputDeviceEvent::GetInputDeviceAsync(int32_t deviceId,
                                           std::function<void(std::shared_ptr<InputDeviceInfo>)> callback)
{
    MMI_LOGI("begin");
    std::lock_guard<std::mutex> guard(lk_);
    inputDevciceRequests_.insert(std::pair<int32_t,
        std::function<void(std::shared_ptr<InputDeviceInfo>)>>(inputDeviceTaskId_, callback));
    MMIEventHdl.GetDevice(inputDeviceTaskId_, deviceId);
    inputDeviceTaskId_++;
    MMI_LOGI("end");
}

void InputDeviceEvent::OnInputDevice(int32_t taskId, int32_t id, std::string name, int32_t deviceType)
{
    MMI_LOGI("begin");
    auto inputDeviceInfo = std::make_shared<InputDeviceInfo>();
    inputDeviceInfo->id = id;
    inputDeviceInfo->name = name;
    inputDeviceInfo->devcieType = deviceType;

    for (const auto &item : inputDevciceRequests_) {
        if (item.first == taskId) {
            item.second(inputDeviceInfo);
        }
    }
    MMI_LOGI("end");
}

void InputDeviceEvent::OnInputDeviceIds(int32_t taskId, std::vector<int32_t> ids)
{
    MMI_LOGI("begin");
    for (const auto &item : idsRequests_) {
        if (item.first == taskId) {
            item.second(ids);
        }
    }
    MMI_LOGI("end");
}
}
}