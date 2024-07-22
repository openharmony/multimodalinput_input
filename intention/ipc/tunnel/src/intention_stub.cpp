/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "intention_stub.h"

#include "devicestatus_define.h"
#include "intention_identity.h"

#undef LOG_TAG
#define LOG_TAG "IntentionStub"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t IntentionStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = IntentionStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        FI_HILOGE("IntentionStub::OnRemoteRequest failed, descriptor is not matched");
        return E_DEVICESTATUS_GET_SERVICE_FAILED;
    }
    Intention intention = static_cast<Intention>(GINTENTION(code));

    switch (GACTION(code)) {
        case CommonAction::ENABLE: {
            return Enable(intention, data, reply);
        }
        case CommonAction::DISABLE: {
            return Disable(intention, data, reply);
        }
        case CommonAction::START: {
            return Start(intention, data, reply);
        }
        case CommonAction::STOP: {
            return Stop(intention, data, reply);
        }
        case CommonAction::ADD_WATCH: {
            return AddWatch(intention, GPARAM(code), data, reply);
        }
        case CommonAction::REMOVE_WATCH: {
            return RemoveWatch(intention, GPARAM(code), data, reply);
        }
        case CommonAction::SET_PARAM: {
            return SetParam(intention, GPARAM(code), data, reply);
        }
        case CommonAction::GET_PARAM: {
            return GetParam(intention, GPARAM(code), data, reply);
        }
        case CommonAction::CONTROL: {
            return Control(intention, GPARAM(code), data, reply);
        }
        default: {
            FI_HILOGE("Unknown action");
        }
    }
    return RET_ERR;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS