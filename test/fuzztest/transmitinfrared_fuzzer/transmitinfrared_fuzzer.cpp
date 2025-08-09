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

#include "transmitinfrared_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"

#undef LOG_TAG
#define LOG_TAG "TransmitInfraredFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {

const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.multimodalinput.IConnectManager" };

bool TransmitInfraredFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        return false;
    }

    int64_t number = *(reinterpret_cast<const int64_t *>(data));
    datas.WriteInt64(number);

    size_t patternCount = (size - sizeof(int64_t)) / sizeof(int64_t);
    for (size_t i = 0; i < patternCount; ++i) {
        int64_t value = *(reinterpret_cast<const int64_t *>(data + sizeof(int64_t) + i * sizeof(int64_t)));
        datas.WriteInt64(value);
    }

    datas.RewindRead(0);

    MessageParcel reply;
    MessageOption option;

    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_TRANSMIT_INFRARED),
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

    OHOS::TransmitInfraredFuzzTest(data, size);
    return 0;
}

} // namespace MMI
} // namespace OHOS