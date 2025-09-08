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

#include "connectproxy_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxyFuzzTest"

namespace OHOS {
namespace MMI {
void SetCustomCursorPixelMapFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    int32_t focusX   = fdp.ConsumeIntegral<int32_t>();
    int32_t focusY   = fdp.ConsumeIntegral<int32_t>();
    CursorPixelMap curPixelMap;
    MULTIMODAL_INPUT_CONNECT_MGR->multimodalInputConnectService_->SetCustomCursorPixelMap(
        windowId, focusX, focusY, curPixelMap);
}

void SetCustomCursorFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    CustomCursorParcel cur;
    cur.focusX = fdp.ConsumeIntegral<int32_t>();
    cur.focusY = fdp.ConsumeIntegral<int32_t>();
    CursorOptionsParcel opt;
    opt.followSystem = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->multimodalInputConnectService_->SetCustomCursor(windowId, cur, opt);
}

void SetMouseIconFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    CursorPixelMap curPixelMap;
    MULTIMODAL_INPUT_CONNECT_MGR->multimodalInputConnectService_->SetMouseIcon(windowId, curPixelMap);
}

void GetCursorSurfaceIdFuzz(FuzzedDataProvider &fdp)
{
    uint64_t surfaceId = fdp.ConsumeIntegral<uint64_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->GetCursorSurfaceId(surfaceId);
}

void SetMouseHotSpotFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    int32_t hotX = fdp.ConsumeIntegral<int32_t>();
    int32_t hotY = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetMouseHotSpot(pid, windowId, hotX, hotY);
}

void ConnectProxyFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    SetCustomCursorPixelMapFuzz(fdp);
    SetCustomCursorFuzz(fdp);
    SetMouseIconFuzz(fdp);
    GetCursorSurfaceIdFuzz(fdp);
    SetMouseHotSpotFuzz(fdp);
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

    OHOS::MMI::ConnectProxyFuzzTest(data, size);
    return 0;
}
