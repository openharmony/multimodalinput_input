/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef KEY_AUTO_REPEAT_H
#define KEY_AUTO_REPEAT_H

#include <map>
#include <string>

#include "event_dispatch_handler.h"
#include "key_event.h"
#include "key_map_manager.h"
#include "libinput.h"
#include "singleton.h"
#include "util.h"

namespace OHOS {
namespace MMI {
class KeyAutoRepeat final {
    DECLARE_DELAYED_SINGLETON(KeyAutoRepeat);
public:
    DISALLOW_COPY_AND_MOVE(KeyAutoRepeat);
    int32_t AddDeviceConfig(struct libinput_device *device);
    void SelectAutoRepeat(const std::shared_ptr<KeyEvent>& keyEvent);
    void AddHandleTimer(int32_t timeout);
    void RemoveDeviceConfig(struct libinput_device *device);
    int32_t GetIntervalTime(int32_t deviceId);
    std::map<int32_t, DeviceConfig> GetDeviceConfig() const;
    void RemoveTimer();
    int32_t SetKeyboardRepeatDelay(int32_t delay);
    int32_t SetKeyboardRepeatRate(int32_t rate);
    int32_t GetKeyboardRepeatDelay(int32_t &delay);
    int32_t GetKeyboardRepeatRate(int32_t &rate);
    int32_t GetRepeatKeyCode() const;
private:
    std::string GetTomlFilePath(const std::string &fileName) const;
    DeviceConfig GetAutoSwitch(int32_t deviceId);
    int32_t PutConfigDataToDatabase(std::string &key, int32_t value);
    int32_t GetConfigDataFromDatabase(std::string &key, int32_t &value);
    int32_t GetDelayTime();
    int32_t GetKeyboardRepeatTime(int32_t deviceId, bool isDelay);

private:
    std::map<int32_t, DeviceConfig> deviceConfig_;
    int32_t timerId_ { -1 };
    int32_t repeatKeyCode_ { -1 };
    std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
};

#define KeyRepeat ::OHOS::DelayedSingleton<KeyAutoRepeat>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // KEY_AUTO_REPEAT_H