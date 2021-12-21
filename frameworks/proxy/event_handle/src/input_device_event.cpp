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
    MMI_LOGE("GetInputDeviceIdsAsync enter");
    std::lock_guard<std::mutex> guard(lk_);
    inputDevciceIdsRequests_.insert(std::pair<int32_t,
        std::function<void(std::vector<int32_t>)>>(this->nextTaskIds_, callback));
    MMIEventHdl.GetDeviceIds(this->nextTaskIds_);
    this->nextTaskIds_++;
}

void InputDeviceEvent::GetInputDeviceAsync(int32_t deviceId,
                                           std::function<void(std::shared_ptr<InputDeviceInfo>)> callback)
{
    std::lock_guard<std::mutex> guard(lk_);
    std::shared_ptr<Item> item = std::make_shared<Item>(this->nextTaskInfo_, callback);
    inputDevciceRequests_.insert(std::pair<int32_t, std::shared_ptr<Item>>(this->nextTaskInfo_, item));
    MMIEventHdl.GetDevice(this->nextTaskInfo_, deviceId);
    this->nextTaskInfo_++;
}

void InputDeviceEvent::OnInputDevice(int32_t taskId, int32_t id, std::string name, int32_t deviceType)
{
    auto inputDeviceInfo = std::make_shared<InputDeviceInfo>();
    inputDeviceInfo->id_ = id;
    inputDeviceInfo->name_ = name;
    inputDeviceInfo->devcieType_ = deviceType;

    for (auto it = inputDevciceRequests_.begin(); it != inputDevciceRequests_.end(); it++) {
        if (it->first == taskId) {
            it->second->callback_(inputDeviceInfo);
        }
    }
}

void InputDeviceEvent::OnInputDeviceIds(int32_t taskId, std::vector<int32_t> ids)
{
    for (auto it = inputDevciceIdsRequests_.begin(); it != inputDevciceIdsRequests_.end(); it++) {
        if (it->first == taskId) {
            it->second(ids);
        }
    }
}
}
}