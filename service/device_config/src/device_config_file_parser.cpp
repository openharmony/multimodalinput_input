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

#include "device_config_file_parser.h"

#include <fstream>
#include <regex>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_device.h"
#include "libinput.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DeviceConfigManagement"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t COMMENT_SUBSCRIPT { 0 };
} // namespace

enum evdev_device_udev_tags {
    EVDEV_UDEV_TAG_INPUT = 1 << 0,
    EVDEV_UDEV_TAG_KEYBOARD = 1 << 1,
    EVDEV_UDEV_TAG_MOUSE = 1 << 2,
    EVDEV_UDEV_TAG_TOUCHPAD = 1 << 3,
    EVDEV_UDEV_TAG_TOUCHSCREEN = 1 << 4,
    EVDEV_UDEV_TAG_TABLET = 1 << 5,
    EVDEV_UDEV_TAG_JOYSTICK = 1 << 6,
    EVDEV_UDEV_TAG_ACCELEROMETER = 1 << 7,
    EVDEV_UDEV_TAG_TABLET_PAD = 1 << 8,
    EVDEV_UDEV_TAG_POINTINGSTICK = 1 << 9,
    EVDEV_UDEV_TAG_TRACKBALL = 1 << 10,
    EVDEV_UDEV_TAG_SWITCH = 1 << 11,
};

std::string DeviceConfigManagement::CombDeviceFileName(struct libinput_device *device) const
{
    CALL_DEBUG_ENTER;
    CHKPS(device);
    uint32_t vendor = libinput_device_get_id_vendor(device);
    uint32_t product = libinput_device_get_id_product(device);
    uint32_t version = libinput_device_get_id_version(device);
    const char *name = libinput_device_get_name(device);
    CHKPS(name);
    std::string fileName =
        std::to_string(vendor) + "_" + std::to_string(product) + "_" + std::to_string(version) + "_" + name;
    RemoveSpace(fileName);
    return fileName;
}

ConfigFileItem DeviceConfigManagement::ConfigItemName2Id(const std::string &name) const
{
    static const std::map<const std::string, ConfigFileItem> configList = {
        { "speed", ConfigFileItem::POINTER_SPEED },
    };

    auto iter = configList.find(name);
    if (iter == configList.end()) {
        MMI_HILOGE("Device name failed");
        return ConfigFileItem::INVALID;
    }
    return configList.at(name);
}

std::map<ConfigFileItem, int32_t> DeviceConfigManagement::ReadConfigFile(const std::string &filePath) const
{
    std::map<ConfigFileItem, int32_t> configList;
    std::ifstream cfgFile(filePath);
    if (!cfgFile.is_open()) {
        MMI_HILOGE("Failed to open config file");
        return configList;
    }
    std::string tmp;

    while (std::getline(cfgFile, tmp)) {
        RemoveSpace(tmp);
        size_t pos = tmp.find('#');
        if (pos != tmp.npos && pos != COMMENT_SUBSCRIPT) {
            continue;
        }
        if (tmp.empty() || tmp.front() == '#') {
            continue;
        }
        pos = tmp.find('=');
        if ((pos == std::string::npos) || (tmp.back() == '=')) {
            continue;
        }
        std::string key = tmp.substr(0, pos);

        std::smatch match;
        bool isNumber = std::regex_search(tmp, match, std::regex("\\d+"));
        if (!isNumber) {
            continue;
        }
        configList[ConfigItemName2Id(key)] = std::stoi(match[0]);
    }
    cfgFile.close();
    return configList;
}

VendorConfig DeviceConfigManagement::GetVendorConfig(struct libinput_device *device) const
{
    CALL_DEBUG_ENTER;
    CHKPO(device);
    std::string filePath = "/vendor/etc/pointer/" + CombDeviceFileName(device) + ".TOML";
    VendorConfig vendorConfigTmp = {};
    auto path = FileVerification(filePath, "TOML");
    if (path.empty()) {
        MMI_HILOGE("File validation failed");
        return vendorConfigTmp;
    }
    auto configList = ReadConfigFile(path);
    if (configList.empty()) {
        MMI_HILOGE("configList is empty");
        return vendorConfigTmp;
    }
    if (configList.find(ConfigFileItem::POINTER_SPEED) == configList.end()) {
        MMI_HILOGE("configList not find POINTER_SPEED");
        return vendorConfigTmp;
    }
    vendorConfigTmp.pointerSpeed = configList[ConfigFileItem::POINTER_SPEED];
    return vendorConfigTmp;
}
} // namespace MMI
} // namespace OHOS