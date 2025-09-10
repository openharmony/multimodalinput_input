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
#include "onenableinputdevice_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LibinputDeviceManagerFuzzTest"

namespace OHOS {
namespace MMI {
void OnEnableInputDeviceFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    bool enable = provider.ConsumeBool();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    deviceInfo.isPointerDevice = provider.ConsumeBool();
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    INPUT_DEV_MGR->devListeners_.push_back(session);
    INPUT_DEV_MGR->OnEnableInputDevice(enable);
}

void GetDeviceConfigFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    int32_t keyboardType = provider.ConsumeIntegral<int32_t>();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    INPUT_DEV_MGR->GetDeviceConfig(deviceId, keyboardType);
}

void NotifyInputdeviceMessageFuzzTest(FuzzedDataProvider &provider)
{
    int32_t index = provider.ConsumeIntegral<int32_t>();
    int32_t result = provider.ConsumeIntegral<int32_t>();
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    INPUT_DEV_MGR->NotifyInputdeviceMessage(session, index, result);
}

void SetInputDeviceEnabledFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    bool enable = provider.ConsumeBool();
    int32_t index = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    INPUT_DEV_MGR->SetInputDeviceEnabled(deviceId, enable, index, pid, session);
}

void RecoverInputDeviceEnabledFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    SessionPtr session = std::shared_ptr<OHOS::MMI::UDSSession>();
    INPUT_DEV_MGR->recoverList_.insert(std::pair<int32_t, int32_t>(deviceId, pid));
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    INPUT_DEV_MGR->RecoverInputDeviceEnabled(session);
}

bool LibinputDeviceManagerFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OnEnableInputDeviceFuzzTest(provider);
    GetDeviceConfigFuzzTest(provider);
    NotifyInputdeviceMessageFuzzTest(provider);
    SetInputDeviceEnabledFuzzTest(provider);
    RecoverInputDeviceEnabledFuzzTest(provider);
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