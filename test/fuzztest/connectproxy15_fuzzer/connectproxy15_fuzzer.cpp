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
#define MMI_LOG_TAG "ConnectProxy15FuzzTest"

namespace OHOS {
namespace MMI {
void SetMouseAccelerateMotionSwitchFuzz(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    bool enable = fdp.ConsumeIntegral<bool>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetMouseAccelerateMotionSwitch(deviceId, enable);
}

void SwitchScreenCapturePermissionFuzz(FuzzedDataProvider &fdp)
{
    uint32_t permissionType = fdp.ConsumeIntegral<uint32_t>();
    bool enable = fdp.ConsumeIntegral<bool>();
    MULTIMODAL_INPUT_CONNECT_MGR->SwitchScreenCapturePermission(permissionType, enable);
}

void QueryPointerRecordFuzz(FuzzedDataProvider &fdp)
{
    int32_t count = fdp.ConsumeIntegral<int32_t>();
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    int32_t eventType = fdp.ConsumeIntegral<int32_t>();
    pointerList.push_back(nullptr);
    auto pointer = std::make_shared<PointerEvent>(eventType);
    pointer->pointerId_ = fdp.ConsumeIntegral<int32_t>();
    pointerList.push_back(pointer);
    pointer->pointerId_ = fdp.ConsumeIntegral<int32_t>();
    pointerList.push_back(pointer);
    MULTIMODAL_INPUT_CONNECT_MGR->QueryPointerRecord(count, pointerList);
}

void ConnectProxy15FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    SetMouseAccelerateMotionSwitchFuzz(fdp);
    SwitchScreenCapturePermissionFuzz(fdp);
    QueryPointerRecordFuzz(fdp);
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

    OHOS::MMI::ConnectProxy15FuzzTest(data, size);
    return 0;
}
