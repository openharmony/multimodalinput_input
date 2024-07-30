/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "inputdevicemanager_fuzzer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceManagerFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {
bool InputDeviceManagerFuzzTest(const uint8_t *data, size_t size)
{
    int32_t id = 1;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    std::string type = "hello";
    bool checked = true;
    bool enable = true;
    bool hasPointerDevice = true;
    bool isVisible = true;
    bool isHotPlug = true;
    libinput_device* deviceOrigin = nullptr;
    std::shared_ptr<InputDevice> inputDevice;
    std::shared_ptr<IDeviceObserver> observer;
    std::shared_ptr<InputDevice> devicePtr = std::make_shared<InputDevice>();
    struct libinput_device* structDevice = nullptr;
    std::vector<int32_t> keyCodes = {1};
    std::vector<bool> keystroke = {true};
    std::vector<std::string> args = {"hello"};
    SessionPtr session;
    InputDeviceManager::InputDeviceInfo inDevice;

    INPUT_DEV_MGR->GetInputDevice(deviceId, checked);
    INPUT_DEV_MGR->FillInputDevice(inputDevice, deviceOrigin);
    INPUT_DEV_MGR->GetInputDeviceIds();
    INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystroke);
    INPUT_DEV_MGR->IsMatchKeys(structDevice, keyCodes);
    INPUT_DEV_MGR->GetDeviceConfig(deviceId, keyboardType);
    INPUT_DEV_MGR->GetKeyboardBusMode(deviceId);
    INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType);
    INPUT_DEV_MGR->AddDevListener(session);
    INPUT_DEV_MGR->RemoveDevListener(session);
    #ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    INPUT_DEV_MGR->HasPointerDevice();
    #endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    INPUT_DEV_MGR->HasTouchDevice();
    INPUT_DEV_MGR->NotifyDevCallback(deviceId, inDevice);
    INPUT_DEV_MGR->ScanPointerDevice();
    INPUT_DEV_MGR->IsKeyboardDevice(devicePtr);
    INPUT_DEV_MGR->Attach(observer);
    INPUT_DEV_MGR->Detach(observer);
    INPUT_DEV_MGR->NotifyPointerDevice(hasPointerDevice, isVisible, isHotPlug);
    INPUT_DEV_MGR->IsRemote(id);
    INPUT_DEV_MGR->GetVendorConfig(deviceId);
    INPUT_DEV_MGR->OnEnableInputDevice(enable);
    INPUT_DEV_MGR->AddVirtualInputDevice(devicePtr, deviceId);
    INPUT_DEV_MGR->RemoveVirtualInputDevice(deviceId);
    INPUT_DEV_MGR->MakeVirtualDeviceInfo(devicePtr, inDevice);
    INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId);
    INPUT_DEV_MGR->NotifyDevRemoveCallback(deviceId, inDevice);
    INPUT_DEV_MGR->NotifyMessage(session, id, type);
    INPUT_DEV_MGR->InitSessionLostCallback();
    INPUT_DEV_MGR->OnSessionLost(session);
    INPUT_DEV_MGR->GetTouchPadIds();
    INPUT_DEV_MGR->IsTouchableDevice(devicePtr);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::InputDeviceManagerFuzzTest(data, size);
    return 0;
}
} // namespace MMI
} // namespace OHOS