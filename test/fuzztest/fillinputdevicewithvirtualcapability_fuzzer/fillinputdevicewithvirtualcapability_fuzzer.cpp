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

#include "mmi_log.h"
#include "input_device_manager.h"
#include "fillinputdevicewithvirtualcapability_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FillInputDeviceWithVirtualCapabilityFuzzTest"

namespace OHOS {
namespace MMI {
bool FillInputDeviceWithVirtualCapabilityFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    auto inputDevice = std::make_shared<InputDevice>();
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isTouchableDevice = provider.ConsumeBool();
    int32_t intDeviceCapability = provider.ConsumeIntegralInRange<int32_t>(0, 10);
    auto deviceCapability = static_cast<MMI::InputDeviceCapability>(intDeviceCapability);
    inputDevice->AddCapability(deviceCapability);
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = inputDevice;
    INPUT_DEV_MGR->FillInputDeviceWithVirtualCapability(inputDevice, deviceInfo);
    return true;
}
} // namespace MMI
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::FillInputDeviceWithVirtualCapabilityFuzzTest(data, size);
    return 0;
}