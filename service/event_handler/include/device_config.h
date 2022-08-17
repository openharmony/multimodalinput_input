/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H

#include <map>
#include <string>
struct libinput_device;

namespace OHOS {
namespace MMI {

enum ConfigFileItem
{
    INVALID = -1,
    POINTER_BASE = 0,
    POINTER_SPEED,
    KEYBOARD_BASE = 1000,
    KEY_XXXX,
};

class DeviceConfigManagement {
public:
    DeviceConfigManagement() = default;
    ~DeviceConfigManagement() = default;
    /*
/etc/mouse/common.conf
button_count = TTTTTTT

/etc/mouse/1a-2b-3c-d.conf   => device id: 30, 35
include /etc/mouse/common.conf
speed = 100
30 => {1 => 100, 2 => 3, }
/etc/mouse/1a-2b-3c-e.conf   => device id: 40
speed = 200

/etc/keyboard/01-20-3c-k.conf   => device id: 10, 15
layout = 104
/etc/keyboard/01-24-3c-l.conf   => device id: 20
layout = 110
     */

public:

    int32_t AddDeviceProfile(struct libinput_device *device);
    void RemoveDeviceProfile(struct libinput_device *device);
    std::string GetEventFileName(struct libinput_device *device);
private:
    typedef int32_t DeviceId;
    std::map<DeviceId, std::map<ConfigFileItem, int32_t>> deviceListConfig;

private:
    int32_t DeviceClassification(struct libinput_device *device, DeviceId deviceId);
    int32_t DeviceConfiguration(struct libinput_device *device, DeviceId deviceId);
    std::map<ConfigFileItem, int32_t> ReadConfigFile(const std::string &filePath);
    ConfigFileItem ConfigItemName2Id(const std::string &name);
};
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_CONFIG_H