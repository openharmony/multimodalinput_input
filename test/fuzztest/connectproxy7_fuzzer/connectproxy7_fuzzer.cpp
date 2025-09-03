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

#include "connectproxy7_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy7FuzzTest"

namespace OHOS {
namespace MMI {
void GetHardwareCursorStatsFuzz(FuzzedDataProvider &fdp)
{
    uint32_t frameCount = fdp.ConsumeIntegral<uint32_t>();
    uint32_t vsyncCount = fdp.ConsumeIntegral<uint32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->GetHardwareCursorStats(frameCount, vsyncCount);
}

void SetMouseCaptureModeFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    bool isCapture = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->SetMouseCaptureMode(windowId, isCapture);
}

void SetTouchpadScrollSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadScrollSwitch(switchFlag);
}

void GetTouchpadScrollSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadScrollSwitch(switchFlag);
}

void SetTouchpadScrollDirectionFuzz(FuzzedDataProvider &fdp)
{
    bool state = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadScrollDirection(state);
}

void ConnectProxy7FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    GetHardwareCursorStatsFuzz(fdp);
    SetMouseCaptureModeFuzz(fdp);
    SetTouchpadScrollSwitchFuzz(fdp);
    GetTouchpadScrollSwitchFuzz(fdp);
    SetTouchpadScrollDirectionFuzz(fdp);
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

    OHOS::MMI::ConnectProxy7FuzzTest(data, size);
    return 0;
}
