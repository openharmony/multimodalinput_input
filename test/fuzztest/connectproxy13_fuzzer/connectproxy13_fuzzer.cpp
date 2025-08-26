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

#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy13FuzzTest"

namespace OHOS {
namespace MMI {
void GetTouchpadScrollRowsFuzz(FuzzedDataProvider &fdp)
{
    int32_t rows = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadScrollRows(rows);
}

void SetInputDeviceEnabledFuzz(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    bool enabled = fdp.ConsumeIntegral<bool>();
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetInputDeviceEnabled(deviceId, enabled, index);
}

void SetMultiWindowScreenIdFuzz(FuzzedDataProvider &fdp)
{
    uint64_t screenId = fdp.ConsumeIntegral<uint64_t>();
    uint64_t displayNodeScreenId = fdp.ConsumeIntegral<uint64_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetMultiWindowScreenId(screenId, displayNodeScreenId);
}

void QuerySwitchStatusFuzz(FuzzedDataProvider &fdp)
{
    int32_t switchType = fdp.ConsumeIntegral<int32_t>();
    int32_t state = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->QuerySwitchStatus(switchType, state);
}

void ConnectProxy13FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    GetTouchpadScrollRowsFuzz(fdp);
    SetInputDeviceEnabledFuzz(fdp);
    SetMultiWindowScreenIdFuzz(fdp);
    QuerySwitchStatusFuzz(fdp);
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

    OHOS::MMI::ConnectProxy13FuzzTest(data, size);
    return 0;
}
