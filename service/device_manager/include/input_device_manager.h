/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INPUT_DEVICE_MANAGER_H
#define INPUT_DEVICE_MANAGER_H

#include <list>
#include <string>

#include "device_observer.h"
#include "event_dispatch_handler.h"
#include "key_event_normalize.h"
#include "input_device.h"
#include "key_auto_repeat.h"
#include "key_map_manager.h"
#include "msg_handler.h"
#include "nocopyable.h"
#include "pointer_drawing_manager.h"
#include "singleton.h"
#include "util.h"

namespace OHOS {
namespace MMI {
class InputDeviceManager final : public IDeviceObject {
    DECLARE_DELAYED_SINGLETON(InputDeviceManager);

    struct InputDeviceInfo {
        struct libinput_device *inputDeviceOrigin { nullptr };
        std::string networkIdOrigin;
        bool isRemote { false };
        bool isPointerDevice { false };
        bool isTouchableDevice { false };
        std::string dhid;
    };
public:
    DISALLOW_COPY_AND_MOVE(InputDeviceManager);
    void OnInputDeviceAdded(struct libinput_device *inputDevice);
    void OnInputDeviceRemoved(struct libinput_device *inputDevice);
    std::vector<int32_t> GetInputDeviceIds() const;
    std::shared_ptr<InputDevice> GetInputDevice(int32_t id) const;
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes, std::vector<bool> &keystroke);
    int32_t FindInputDeviceId(struct libinput_device* inputDevice);
    int32_t GetKeyboardBusMode(int32_t deviceId);
    bool GetDeviceConfig(int32_t deviceId, int32_t &KeyboardType);
    int32_t GetDeviceSupportKey(int32_t deviceId, int32_t &keyboardType);
    int32_t GetKeyboardType(int32_t deviceId, int32_t &keyboardType);
    void Attach(std::shared_ptr<IDeviceObserver> observer);
    void Detach(std::shared_ptr<IDeviceObserver> observer);
    void NotifyPointerDevice(bool hasPointerDevice, bool isVisible);
    void AddDevListener(SessionPtr sess, std::function<void(int32_t, const std::string&)> callback);
    void RemoveDevListener(SessionPtr sess);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    void DumpDeviceList(int32_t fd, const std::vector<std::string> &args);
    bool IsRemote(struct libinput_device *inputDevice) const;
    bool IsRemote(int32_t id) const;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::string GetOriginNetworkId(int32_t id);
    std::string GetOriginNetworkId(const std::string &dhid);
    std::string GetDhid(int32_t deviceId) const;
    std::vector<std::string> GetCooperateDhids(int32_t deviceId);
    std::vector<std::string> GetCooperateDhids(const std::string &dhid);
    bool HasLocalPointerDevice() const;
    void NotifyVirtualKeyBoardStatus(int32_t deviceId, bool isAvailable) const;
#endif // OHOS_BUILD_ENABLE_COOPERATE
    bool IsKeyboardDevice(struct libinput_device* device) const;
    bool IsPointerDevice(struct libinput_device* device) const;
    bool IsTouchDevice(struct libinput_device* device) const;
    struct libinput_device* GetKeyboardDevice() const;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool HasPointerDevice();
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool HasTouchDevice();
    int32_t SetInputDevice(const std::string& dhid, const std::string& screenId);
    const std::string& GetScreenId(int32_t deviceId) const;

private:
    int32_t ParseDeviceId(const std::string &sysName);
    void MakeDeviceInfo(struct libinput_device *inputDevice, struct InputDeviceInfo& info);
    bool IsMatchKeys(struct libinput_device* device, const std::vector<int32_t> &keyCodes) const;
    void ScanPointerDevice();
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    std::string MakeNetworkId(const char *phys) const;
    std::string Sha256(const std::string &in) const;
    std::string GenerateDescriptor(struct libinput_device *inputDevice, bool isRemote) const;
#endif // OHOS_BUILD_ENABLE_COOPERATE
    std::map<int32_t, struct InputDeviceInfo> inputDevice_;
    std::map<std::string, std::string> inputDeviceScreens_;
    std::list<std::shared_ptr<IDeviceObserver>> observers_;
    std::map<SessionPtr, std::function<void(int32_t, const std::string&)>> devListener_;
};

#define InputDevMgr ::OHOS::DelayedSingleton<InputDeviceManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_MANAGER_H
