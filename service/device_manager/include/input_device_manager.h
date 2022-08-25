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
#include "event_dispatch.h"
#include "key_event_handler.h"
#include "input_device.h"
#include "key_auto_repeat.h"
#include "key_map_manager.h"
#include "msg_handler.h"
#include "nocopyable.h"
#include "singleton.h"
#include "util.h"

namespace OHOS {
namespace MMI {
class InputDeviceManager : public DelayedSingleton<InputDeviceManager>, public IDeviceObject {
public:
    InputDeviceManager() = default;
    DISALLOW_COPY_AND_MOVE(InputDeviceManager);
    void OnInputDeviceAdded(struct libinput_device *inputDevice);
    void OnInputDeviceRemoved(struct libinput_device *inputDevice);
    std::vector<int32_t> GetInputDeviceIds() const;
    std::shared_ptr<InputDevice> GetInputDevice(int32_t id) const;
    std::vector<bool> SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes);
    int32_t FindInputDeviceId(struct libinput_device* inputDevice);
    int32_t GetKeyboardBusMode(int32_t deviceId);
    bool GetDeviceConfig(int32_t deviceId, int32_t &KeyboardType);
    int32_t GetDeviceSupportKey(int32_t deviceId);
    int32_t GetKeyboardType(int32_t deviceId);
    void Attach(std::shared_ptr<IDeviceObserver> observer);
    void Detach(std::shared_ptr<IDeviceObserver> observer);
    void NotifyPointerDevice(bool hasPointerDevice);
    void AddDevListener(SessionPtr sess, std::function<void(int32_t, const std::string&)> callback);
    void RemoveDevListener(SessionPtr sess);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    void DumpDeviceList(int32_t fd, const std::vector<std::string> &args);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool HasPointerDevice();
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t SetInputDevice(const std::string& dhid, const std::string& screenId);
    const std::string& GetScreenId(int32_t deviceId) const;

private:
    bool IsPointerDevice(struct libinput_device* device);
    void ScanPointerDevice();
    std::map<int32_t, struct libinput_device *> inputDevice_;
    std::map<std::string, std::string> inputDeviceScreens_;
    int32_t nextId_ {0};
    std::list<std::shared_ptr<IDeviceObserver>> observers_;
    std::map<SessionPtr, std::function<void(int32_t, const std::string&)>> devListener_;
};

#define InputDevMgr InputDeviceManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_MANAGER_H
