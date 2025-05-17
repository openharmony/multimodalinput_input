/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "input_device_consumer.h"

#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceConsumer"

namespace OHOS {
namespace MMI {
InputDeviceConsumer::InputDeviceConsumer() {}
InputDeviceConsumer::~InputDeviceConsumer() {}

int32_t InputDeviceConsumer::SetInputDeviceConsumer(const std::vector<std::string>& deviceNames,
    std::shared_ptr<IInputEventConsumer> consumer)
{
    CALL_DEBUG_ENTER;
    if (consumer == nullptr) {
        return MULTIMODAL_INPUT_CONNECT_MGR->ClearInputDeviceConsumer(deviceNames);
    }
    deviceConsumer_ = consumer;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetInputDeviceConsumer(deviceNames);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS
