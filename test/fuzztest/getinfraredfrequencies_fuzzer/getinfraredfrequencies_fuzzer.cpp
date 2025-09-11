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

#include "getinfraredfrequencies_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"

#undef LOG_TAG
#define LOG_TAG "GetInfraredFrequenciesFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {

const std::u16string FORMMGR_INTERFACE_TOKEN = IMultimodalInputConnect::GetDescriptor();

bool GetInfraredFrequenciesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) ||
        !datas.RewindRead(0)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_INFRARED_FREQUENCIES),
        datas, reply, option);

    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    OHOS::GetInfraredFrequenciesFuzzTest(data, size);
    return 0;
}

} // namespace MMI
} // namespace OHOS