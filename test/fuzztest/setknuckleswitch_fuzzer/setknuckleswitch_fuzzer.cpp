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

#include "setknuckleswitch_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

#undef LOG_TAG
#define LOG_TAG "SetKnuckleSwitchFuzzTest"

namespace OHOS {
namespace MMI {

namespace {
const std::u16string kInterfaceToken = IMultimodalInputConnect::GetDescriptor();
} // namespace

bool SetKnuckleSwitchFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(kInterfaceToken)) {
        return false;
    }

    bool knuckleSwitch = provider.ConsumeBool();
    if (!datas.WriteBool(knuckleSwitch)) {
        return false;
    }

    if (!datas.RewindRead(0)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    (void)MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SET_KNUCKLE_SWITCH),
        datas, reply, option);

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    (void)OHOS::MMI::SetKnuckleSwitchFuzzTest(provider);
    return 0;
}

} // namespace MMI
} // namespace OHOS