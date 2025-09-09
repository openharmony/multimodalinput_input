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

#include "connectproxy6_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy6FuzzTest"

namespace OHOS {
namespace MMI {
void SetTouchpadThreeFingersTapSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadThreeFingersTapSwitch(switchFlag);
}

void GetTouchpadThreeFingersTapSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadThreeFingersTapSwitch(switchFlag);
}

void AddVirtualInputDeviceFuzz(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    device->SetId(fdp.ConsumeIntegral<int32_t>());
    device->SetType((fdp.ConsumeIntegral<int32_t>()));
    device->SetName(fdp.ConsumeRandomLengthString());
    MULTIMODAL_INPUT_CONNECT_MGR->AddVirtualInputDevice(device, deviceId);
}

void RemoveVirtualInputDeviceFuzz(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->RemoveVirtualInputDevice(deviceId);
}

void EnableHardwareCursorStatsFuzz(FuzzedDataProvider &fdp)
{
    bool enable = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->EnableHardwareCursorStats(enable);
}

void ConnectProxy6FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    SetTouchpadThreeFingersTapSwitchFuzz(fdp);
    GetTouchpadThreeFingersTapSwitchFuzz(fdp);
    AddVirtualInputDeviceFuzz(fdp);
    RemoveVirtualInputDeviceFuzz(fdp);
    EnableHardwareCursorStatsFuzz(fdp);
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

    OHOS::MMI::ConnectProxy6FuzzTest(data, size);
    return 0;
}
