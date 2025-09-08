/*
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
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

#include <message_parcel.h>
#include "input_device_consumer_proxy.h"
#include "parcel.h"
#include "string_ex.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceConsumerProxy"

namespace OHOS {
namespace MMI {
int32_t IInputDeviceConsumerProxy::SendInputDeviceConsumerHandler(
    const std::vector<std::string> &deviceNames, CODE code)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(IInputDeviceConsumer::GetDescriptor())) {
        MMI_HILOGE("Write interface token failed!");
        return MSG_SEND_FAIL;
    }

    uint32_t size = deviceNames.size();
    if (!data.WriteUint32(size)) {
        MMI_HILOGE("Write device name size failed!");
        return MSG_SEND_FAIL;
    }
    for (const auto& name : deviceNames) {
        if (!data.WriteString(name)) {
            MMI_HILOGE("Write device name failed!");
            return MSG_SEND_FAIL;
        }
    }

    int32_t ret = Remote()->SendRequest(code, data, reply, option);
    if (ret != RET_OK) {
        MMI_HILOGE("Send request failed!");
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t IInputDeviceConsumerProxy::SetInputDeviceConsumerHandler(const std::vector<std::string> &deviceNames)
{
    return SendInputDeviceConsumerHandler(deviceNames, CODE::CODE_SET_INPUT_DEVICE_CONSUMER_HANDLER);
}

int32_t IInputDeviceConsumerProxy::ClearInputDeviceConsumerHandler(const std::vector<std::string> &deviceNames)
{
    return SendInputDeviceConsumerHandler(deviceNames, CODE::CODE_CLEAR_INPUT_DEVICE_CONSUMER_HANDLER);
}
} // namespace MMI
} // namespace OHOS