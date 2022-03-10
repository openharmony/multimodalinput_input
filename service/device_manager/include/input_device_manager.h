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
#include "util.h"
#include "singleton.h"
#include "../../../common/include/device_observer.h"
#include "msg_handler.h"
#include "event_dispatch.h"
#include "event_package.h"
#include "input_device.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class InputDeviceManager : public DelayedSingleton<InputDeviceManager>, public Subject {
public:
    InputDeviceManager() = default;
    DISALLOW_COPY_AND_MOVE(InputDeviceManager);
    void OnInputDeviceAdded(struct libinput_device* inputDevice);
    void OnInputDeviceRemoved(struct libinput_device* inputDevice);
    std::vector<int32_t> GetInputDeviceIds() const;
    std::shared_ptr<InputDevice> GetInputDevice(int32_t id) const;
    void GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback);
    void FindInputDeviceIdAsync(int32_t deviceId, std::function<void(std::shared_ptr<InputDevice>)> callback);
    int32_t FindInputDeviceId(struct libinput_device* inputDevice);
    void Attach(std::shared_ptr<DeviceObserver> observer);
    void Detach(std::shared_ptr<DeviceObserver> observer);
    void NotifyPointerDevice(bool hasPointerDevice);

private:
    bool IsPointerDevice(libinput_device* device);
    std::map<int32_t, struct libinput_device*> inputDevice_;
    bool initFlag_ {false};
    int32_t nextId_ {0};
    std::list<std::shared_ptr<DeviceObserver>> observers_;
};
} // namespace MMI
} // namespace OHOS
#define InputDevMgr OHOS::MMI::InputDeviceManager::GetInstance()
#endif // INPUT_DEVICE_MANAGER_H