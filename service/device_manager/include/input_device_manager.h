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
#include "message_post.h"

namespace OHOS {
namespace MMI {
class InputDeviceManager : public DelayedSingleton<InputDeviceManager>, public Subject {
public:
    void OnInputDeviceAdded(libinput_device* inputDevice);
    void OnInputDeviceRemoved(libinput_device* inputDevice);
    std::vector<int32_t> GetInputDeviceIds();
    std::shared_ptr<InputDevice> GetInputDevice(int32_t id);
    void GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback);
    void FindInputDeviceIdAsync(int32_t deviceId, std::function<void(std::shared_ptr<InputDevice>)> callback);
    int32_t FindInputDeviceId(libinput_device* inputDevice);
    void Attach(std::shared_ptr<DeviceObserver> observer);
    void Detach(std::shared_ptr<DeviceObserver> observer);
    void NotifyPointerDevice(bool hasPointerDevice);

private:
#ifdef OHOS_WESTEN_MODEL
    void Init(weston_compositor *wc);
    std::vector<int32_t> GetInputDeviceIdsSync(weston_compositor *wc);
    std::shared_ptr<InputDevice> FindInputDeviceIdSync(int32_t deviceId, weston_compositor *wc);
#endif
    bool IsPointerDevice(libinput_device* device);

    std::map<int32_t, libinput_device*> inputDevice_;
    bool initFlag_ {false};
    int32_t nextId_ {0};
    std::list<std::shared_ptr<DeviceObserver>> observers_;
};
} // namespace MMI
} // namespace OHOS
#define InputDevMgr OHOS::MMI::InputDeviceManager::GetInstance()
#endif // INPUT_DEVICE_MANAGER_H