/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DEVICE_CONFIG_FILE_PARSER_H
#define DEVICE_CONFIG_FILE_PARSER_H

#include <map>

struct libinput_device;

struct VendorConfig {
    int32_t pointerSpeed { -1 };
};

namespace OHOS {
namespace MMI {
enum class ConfigFileItem {
    INVALID = -1,
    POINTER_BASE = 0,
    POINTER_SPEED,
};
class DeviceConfigManagement {
public:
    DeviceConfigManagement() = default;
    ~DeviceConfigManagement() = default;
public:
    VendorConfig GetVendorConfig(struct libinput_device *device) const;

private:
    std::string CombDeviceFileName(struct libinput_device *device) const;
    std::map<ConfigFileItem, int32_t> ReadConfigFile(const std::string &filePath) const;
    ConfigFileItem ConfigItemName2Id(const std::string &name) const;
};
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_CONFIG_FILE_PARSER_H