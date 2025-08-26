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
#include "input_device_consumer_proxy.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

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
    MMI_HILOGD("Set input device consumer start");
    sptr<IRemoteObject> inputDevicePluginStub = nullptr;
    const std::string pluginName = "pc.pointer.inputDeviceConsumer.202507";
    MULTIMODAL_INPUT_CONNECT_MGR->GetPluginRemoteStub(pluginName, inputDevicePluginStub);
    if (!inputDevicePluginStub) {
        MMI_HILOGE("Get input device stub from plugin failed");
        return ERROR_NO_PERMISSION;
    }

    sptr<IInputDeviceConsumerProxy> inputDevicePluginProxy =
        sptr<IInputDeviceConsumerProxy>::MakeSptr(inputDevicePluginStub);
    if (!inputDevicePluginProxy) {
        MMI_HILOGE("Transfer input device plugin stub to proxy failed");
        return ERROR_NO_PERMISSION;
    }

    std::lock_gaurd<std::mutex> guard(mtx_);
    deviceConsumer_ = consumer;
    if (consumer == nullptr) {
        MMI_HILOGE("The input event consumer is nullptr");
        return inputDevicePluginProxy->ClearInputDeviceConsumerHandler(deviceNames);
    }
    int32_t ret = inputDevicePluginProxy->SetInputDeviceConsumerHandler(deviceNames);
    if (ret != RET_OK) {
        MMI_HILOGE("Set input device consumer by plugin falied, ret:%{public}d", ret);
    }
    deviceNames_ = deviceNames;
    return ret;
}

void InputDeviceConsumer::OnConnected()
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Set input device consumer start when connected");
    std::lock_guard<std::mutex> guard(mtx_);
    if (deviceNames_.empty()) {
        return;
    }

    sptr<IInputDeviceConsumerProxy> inputDevicePluginProxy =
        sptr<IInputDeviceConsumerProxy>::MakeSptr(inputDevicePluginStub);
    if (!inputDevicePluginProxy) {
        MMI_HILOGE("Transfer input device plugin stub to proxy failed");
        return;
    }
    inputDevicePluginProxy->SetInputDeviceConsumerHandler(deviceNames_);
}
} // namespace MMI
} // namespace OHOS
