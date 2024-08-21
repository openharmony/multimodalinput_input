/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
 
#ifndef LIBINPUT_ADAPTER_H
#define LIBINPUT_ADAPTER_H

#include <array>
#include <functional>
#include <thread>
#include <unordered_map>

#include "hotplug_detector.h"
#include "libinput.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
typedef std::function<void(void *event, int64_t frameTime)> FunInputEvent;
class LibinputAdapter final {
public:
    static int32_t DeviceLedUpdate(struct libinput_device *device, int32_t funcKey, bool isEnable);
    LibinputAdapter() = default;
    DISALLOW_COPY_AND_MOVE(LibinputAdapter);
    ~LibinputAdapter() = default;
    bool Init(FunInputEvent funInputEvent);
    void EventDispatch(int32_t fd);
    void Stop();
    void ProcessPendingEvents();
    void ReloadDevice();

    auto GetInputFds() const
    {
        return std::array{fd_, hotplugDetector_.GetFd()};
    }

private:
    void OnEventHandler();
    void OnDeviceAdded(std::string path);
    void OnDeviceRemoved(std::string path);
    void InitRightButtonAreaConfig();

    int32_t fd_ { -1 };
    libinput *input_ { nullptr };

    FunInputEvent funInputEvent_;

    HotplugDetector hotplugDetector_;
    std::unordered_map<std::string, libinput_device*> devices_;
};
} // namespace MMI
} // namespace OHOS
#endif // S_INPUT_H
