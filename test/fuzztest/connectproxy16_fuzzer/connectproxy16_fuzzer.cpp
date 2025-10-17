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
#define MMI_LOG_TAG "ConnectProxy16FuzzTest"

namespace OHOS {
namespace MMI {
void SetPointerVisibleFuzz(FuzzedDataProvider &fdp)
{
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    bool visible = fdp.ConsumeIntegral<bool>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetPointerVisible(visible, priority);
}

void IsPointerVisibleFuzz(FuzzedDataProvider &fdp)
{
    bool visible = fdp.ConsumeIntegral<bool>();
    MULTIMODAL_INPUT_CONNECT_MGR->IsPointerVisible(visible);
}

void MoveMouseEventFuzz(FuzzedDataProvider &fdp)
{
    int32_t offsetX = fdp.ConsumeIntegral<int32_t>();
    int32_t offsetY = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->MoveMouseEvent(offsetX, offsetY);
}

void SetPointerLocationFuzz(FuzzedDataProvider &fdp)
{
    int32_t x = fdp.ConsumeIntegral<int32_t>();
    int32_t y = fdp.ConsumeIntegral<int32_t>();
    int32_t displayId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetPointerLocation(x, y, displayId);
}

void GetPointerLocationFuzz(FuzzedDataProvider &fdp)
{
    double displayX = fdp.ConsumeFloatingPoint<double>();
    double displayY = fdp.ConsumeFloatingPoint<double>();
    int32_t displayId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->GetPointerLocation(displayId, displayX, displayY);
}

void ConnectProxy16FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    SetPointerVisibleFuzz(fdp);
    IsPointerVisibleFuzz(fdp);
    MoveMouseEventFuzz(fdp);
    SetPointerLocationFuzz(fdp);
    GetPointerLocationFuzz(fdp);
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

    OHOS::MMI::ConnectProxy16FuzzTest(data, size);
    return 0;
}
