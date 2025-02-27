/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_INPUT_DEVICE_LISTENER_H
#define OH_INPUT_DEVICE_LISTENER_H

#include <mutex>

#include "i_input_device_listener.h"

namespace OHOS {
namespace MMI {
class OHInputDeviceListener : public OHOS::MMI::IInputDeviceListener,
    public std::enable_shared_from_this<OHInputDeviceListener> {
public:
    OHInputDeviceListener();
    ~OHInputDeviceListener();
    void OnDeviceAdded(int32_t deviceId, const std::string &type) override;
    void OnDeviceRemoved(int32_t deviceId, const std::string &type) override;
    void SetDeviceAddedCallback(const std::function<void(int32_t deviceId, const std::string &type)> &callback);
    void SetDeviceRemovedCallback(const std::function<void(int32_t deviceId, const std::string &type)> &callback);

private:
    std::function<void(int32_t deviceId, const std::string &type)> addCallbacks_;
    std::function<void(int32_t deviceId, const std::string &type)> removeCallbacks_;
};
}
}
#endif