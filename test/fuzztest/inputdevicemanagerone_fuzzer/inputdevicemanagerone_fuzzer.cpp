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
#include "inputdevicemanagerone_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceManagerOneFuzzTest"

namespace OHOS {
namespace MMI {
void NotifyMessageFuzzTest(FuzzedDataProvider &provider)
{
    auto session = std::shared_ptr<OHOS::MMI::UDSSession>();
    int32_t id = provider.ConsumeIntegral<int32_t>();
    std::string type = provider.ConsumeBytesAsString(20);
    INPUT_DEV_MGR->NotifyMessage(session, id, type);
}

void GenerateVirtualDeviceIdFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    auto device = std::make_shared<InputDevice>();
    INPUT_DEV_MGR->virtualInputDevices_[deviceId] = device;
    INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId);
}

void GetInputDeviceFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    bool checked = provider.ConsumeBool();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    INPUT_DEV_MGR->GetInputDevice(deviceId, checked);
}

void SupportKeysFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    std::vector<int32_t> keyCodes = {
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>()
    };
    std::vector<bool> keystroke = {
        provider.ConsumeBool(),
        provider.ConsumeBool()
    };
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isRemote = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystroke);
}

void NotifyDevCallbackFuzzTest(FuzzedDataProvider &provider)
{
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.isTouchableDevice = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    INPUT_DEV_MGR->NotifyDevCallback(deviceId, deviceInfo);
}

bool InputDeviceManagerOneFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    NotifyMessageFuzzTest(provider);
    GenerateVirtualDeviceIdFuzzTest(provider);
    GetInputDeviceFuzzTest(provider);
    SupportKeysFuzzTest(provider);
    NotifyDevCallbackFuzzTest(provider);
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

    OHOS::MMI::InputDeviceManagerOneFuzzTest(data, size);
    return 0;
}