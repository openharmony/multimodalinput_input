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
#include "notifyaddpointerdevice_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LibinputDeviceManagerFuzzTest"

namespace OHOS {
namespace MMI {
void NotifyAddPointerDeviceFuzzTest(FuzzedDataProvider &provider)
{
    bool addNewPointerDevice = provider.ConsumeBool();
    bool existEnabledPointerDevice = provider.ConsumeBool();
    INPUT_DEV_MGR->NotifyAddPointerDevice(addNewPointerDevice, existEnabledPointerDevice);
}

void NotifyRemoveDeviceListenersFuzzTest(FuzzedDataProvider &provider)
{
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    INPUT_DEV_MGR->devListeners_.push_back(session);
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    INPUT_DEV_MGR->NotifyRemoveDeviceListeners(deviceId);
}

void NotifyAddDeviceListenersFuzzTest(FuzzedDataProvider &provider)
{
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    INPUT_DEV_MGR->devListeners_.push_back(session);
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    INPUT_DEV_MGR->NotifyAddDeviceListeners(deviceId);
}

void NotifyDevRemoveCallbackFuzzTest(FuzzedDataProvider &provider)
{
    int32_t strLength = 5;
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isTouchableDevice = provider.ConsumeBool();
    deviceInfo.sysUid = provider.ConsumeBytesAsString(strLength);
    INPUT_DEV_MGR->NotifyDevRemoveCallback(deviceId, deviceInfo);
}

void RemoveVirtualInputDeviceInnerFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isTouchableDevice = provider.ConsumeBool();
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;
    INPUT_DEV_MGR->RemoveVirtualInputDeviceInner(deviceId, deviceInfo);
}

bool LibinputDeviceManagerFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    NotifyAddPointerDeviceFuzzTest(provider);
    NotifyRemoveDeviceListenersFuzzTest(provider);
    NotifyAddDeviceListenersFuzzTest(provider);
    NotifyDevRemoveCallbackFuzzTest(provider);
    RemoveVirtualInputDeviceInnerFuzzTest(provider);
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

    OHOS::MMI::LibinputDeviceManagerFuzzTest(data, size);
    return 0;
}