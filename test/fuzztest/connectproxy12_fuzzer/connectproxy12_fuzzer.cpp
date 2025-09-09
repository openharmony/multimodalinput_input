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

#include "connectproxy12_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy12FuzzTest"

namespace OHOS {
namespace MMI {
void HasIrEmitterFuzz(FuzzedDataProvider &fdp)
{
    bool hasIrEmitter = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->HasIrEmitter(hasIrEmitter);
}

void GetInfraredFrequenciesFuzz(FuzzedDataProvider &fdp)
{
    std::vector<InfraredFrequency> requencys;
    InfraredFrequency requency;
    requency.max_ = fdp.ConsumeIntegral<int64_t>();
    requency.min_ = fdp.ConsumeIntegral<int64_t>();
    requencys.push_back(requency);

    requency.max_ = fdp.ConsumeIntegral<int64_t>();
    requency.min_ = fdp.ConsumeIntegral<int64_t>();
    requencys.push_back(requency);

    requency.max_ = fdp.ConsumeIntegral<int64_t>();
    requency.min_ = fdp.ConsumeIntegral<int64_t>();
    requencys.push_back(requency);

    requency.max_ = fdp.ConsumeIntegral<int64_t>();
    requency.min_ = fdp.ConsumeIntegral<int64_t>();
    requencys.push_back(requency);

    MULTIMODAL_INPUT_CONNECT_MGR->GetInfraredFrequencies(requencys);
}

void TransmitInfraredFuzz(FuzzedDataProvider &fdp)
{
    int64_t number = fdp.ConsumeIntegral<int64_t>();
    std::vector<int64_t> pattern = {
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int64_t>()
    };
    MULTIMODAL_INPUT_CONNECT_MGR->TransmitInfrared(number, pattern);
}

void SetPixelMapDataFuzz(FuzzedDataProvider &fdp)
{
    int32_t infoId = fdp.ConsumeIntegral<int32_t>();
    CursorPixelMap curPixelMap {};
    MULTIMODAL_INPUT_CONNECT_MGR->multimodalInputConnectService_->SetPixelMapData(infoId, curPixelMap);
}

void SetTouchpadScrollRowsFuzz(FuzzedDataProvider &fdp)
{
    int32_t rows = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadScrollRows(rows);
}

void ConnectProxy12FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    HasIrEmitterFuzz(fdp);
    GetInfraredFrequenciesFuzz(fdp);
    TransmitInfraredFuzz(fdp);
    SetPixelMapDataFuzz(fdp);
    SetTouchpadScrollRowsFuzz(fdp);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::ConnectProxy12FuzzTest(data, size);
    return 0;
}
