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

#include "inputdevicemanager_fuzzer.h"

#include "mmi_log.h"
#include "input_device_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceManagerFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {
bool InputDeviceManagerFuzzTest(const uint8_t *data, size_t size)
{
    const std::u16string FORMMGR_INTERFACE_TOKEN{ u"ohos.multimodalinput.IConnectManager" };
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) || !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }

    int32_t id = 1;
    int32_t fd = 1;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    std::string type = "hello";
    bool checked = true;
    bool enable = true;
    bool hasPointerDevice = true;
    bool isVisible = true;
    bool isHotPlug = true;
    struct libinput_device *device = nullptr;
    libinput_device * deviceOrigin = nullptr;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_T);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    std::vector<int32_t> keyCodes = {1};
    std::vector<bool> keystroke = {true};
    std::vector<std::string> args = {"hello"};
    SessionPtr session;
    SessionPtr sess;
    struct InputDeviceInfo inDevice;
    shared_ptr<IDeviceObserver> observer = nullptr;
    INPUT_DEV_MGR->GetInputDevice(deviceId, checked);
    INPUT_DEV_MGR->FillInputDevice(std::shared_ptr<InputDevice> inputDevice, deviceOrigin);
    INPUT_DEV_MGR->GetInputDeviceIds();
    INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystroke);
    INPUT_DEV_MGR->IsMatchKeys(device, keyCodes);
    INPUT_DEV_MGR->GetDeviceConfig(deviceId, keyboardType);
    INPUT_DEV_MGR->GetKeyboardBusMode(deviceId);
    INPUT_DEV_MGR->GetDeviceSupportKey(deviceId, keyboardType);
    INPUT_DEV_MGR->GetKeyboardType(deviceId, keyboardType);
    INPUT_DEV_MGR->AddDevListener(sess);
    INPUT_DEV_MGR->RemoveDevListener(sess);
    ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    INPUT_DEV_MGR->HasPointerDevice();
    endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    INPUT_DEV_MGR->HasTouchDevice();
    INPUT_DEV_MGR->GetInputIdentification(device);
    INPUT_DEV_MGR->NotifyDevCallback(deviceId, inDevice);
    INPUT_DEV_MGR->ParseDeviceId(device);
    INPUT_DEV_MGR->OnInputDeviceAdded(device);
    INPUT_DEV_MGR->MakeDeviceInfo(device, struct InputDeviceInfo & info);
    INPUT_DEV_MGR->OnInputDeviceRemoved(device);
    INPUT_DEV_MGR->ScanPointerDevice();
    INPUT_DEV_MGR->IsPointerDevice(device);
    INPUT_DEV_MGR->IsKeyboardDevice(device);
    INPUT_DEV_MGR->IsTouchDevice(device);
    INPUT_DEV_MGR->Attach(std::shared_ptr<IDeviceObserver> observer);
    INPUT_DEV_MGR->Detach(std::shared_ptr<IDeviceObserver> observer);
    INPUT_DEV_MGR->NotifyPointerDevice(hasPointerDevice, isVisible, isHotPlug);
    INPUT_DEV_MGR->FindInputDeviceId(device);
    INPUT_DEV_MGR->Dump(fd, args);
    INPUT_DEV_MGR->DumpDeviceList(fd, args);
    INPUT_DEV_MGR->IsRemote(device);
    INPUT_DEV_MGR->IsRemote(id);
    INPUT_DEV_MGR->GetVendorConfig(deviceId);
    INPUT_DEV_MGR->OnEnableInputDevice(enable);
    INPUT_DEV_MGR->AddVirtualInputDevice(std::shared_ptr<InputDevice> device, deviceId);
    INPUT_DEV_MGR->RemoveVirtualInputDevice(deviceId);
    INPUT_DEV_MGR->MakeVirtualDeviceInfo(std::shared_ptr<InputDevice> device, InputDeviceInfo & deviceInfo);
    INPUT_DEV_MGR->GenerateVirtualDeviceId(deviceId);
    INPUT_DEV_MGR->NotifyDevRemoveCallback(deviceId, const InputDeviceInfo &deviceInfo);
    INPUT_DEV_MGR->NotifyMessage(session, id, type);
    INPUT_DEV_MGR->InitSessionLostCallback();
    INPUT_DEV_MGR->OnSessionLost(session);
    INPUT_DEV_MGR->GetTouchPadIds();
    INPUT_DEV_MGR->IsPointerDevice(std::shared_ptr<InputDevice> inputDevice);
    INPUT_DEV_MGR->IsTouchableDevice(std::shared_ptr<InputDevice> inputDevice);
    INPUT_DEV_MGR->IsKeyboardDevice(std::shared_ptr<InputDevice> inputDevice);
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