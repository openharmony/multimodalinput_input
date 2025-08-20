/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "onremoterequest_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_service.h"
#include "mmi_log.h"

#undef LOG_TAG
#define LOG_TAG "OnRemoteRequestFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {
const std::u16string FORMMGR_INTERFACE_TOKEN = IMultimodalInputConnect::GetDescriptor();

bool OnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) || !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    FuzzedDataProvider provider(data, size);
    uint32_t enumMax = static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_QUERY_POINTER_RECORD);
    uint32_t code = provider.ConsumeIntegralInRange<uint32_t>(0, enumMax + 1);
    MMIService::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
} // namespace MMI
} // namespace OHOS