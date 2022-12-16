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

#include "device_config_file_parser.h"

#include <fstream>
#include <regex>

#include "error_multimodal.h"
#include "input_device.h"
#include "input_device_manager.h"
#include "libinput.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "DeviceConfigManagement" };
constexpr int32_t INVALID_DEVICE_ID = -1;
constexpr int32_t COMMENT_SUBSCRIPT = 0;
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

std::string DeviceConfigManagement::CombDeviceFileName(struct libinput_device *device)
{
    CALL_DEBUG_ENTER;
    CHKPS(device);
    uint32_t vendor = libinput_device_get_id_vendor(device);
    uint32_t product = libinput_device_get_id_product(device);
    uint32_t version = libinput_device_get_id_version(device);
    const char *name = libinput_device_get_name(device);
    CHKPS(name);
    std::string fileName = std::to_string(vendor) + "_" + std::to_string(product) + "_" +
        std::to_string(version) + "_" + name;
    RemoveSpace(fileName);
    return fileName;
}

ConfigFileItem DeviceConfigManagement::ConfigItemName2Id(const std::string &name)
{
    static const std::map<const std::string, ConfigFileItem> configList = {
        {"speed", ConfigFileItem::POINTER_SPEED},
    };

    auto iter = configList.find(name);
    if (iter == configList.end()) {
        MMI_HILOGE("Device name failed");
        return ConfigFileItem::INVALID;
    }
    return configList.at(name);
}

std::map<ConfigFileItem, int32_t> DeviceConfigManagement::ReadConfigFile(const std::string &filePath)
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
        if (pos == (tmp.size() - 1) || pos == tmp.npos) {
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

int32_t DeviceConfigManagement::DeviceConfiguration(struct libinput_device *device, DeviceId deviceId)
{
    CALL_DEBUG_ENTER;
    std::string filePath = "/vendor/etc/pointer/" + CombDeviceFileName(device) + ".TOML";
    auto path = FileVerification(filePath, "TOML");
    if(path.empty()) {
        MMI_HILOGE("File validation failed");
        return RET_ERR;
    }
    auto configList = ReadConfigFile(path);
    if (configList.empty()) {
        MMI_HILOGE("configList is empty");
        return RET_ERR;
    }
    deviceConfigs_[deviceId] = configList;
    MouseEventHdr->SetPointerSpeedWithDeviceId(deviceId, configList[ConfigFileItem::POINTER_SPEED]);
    return RET_OK;
}

int32_t DeviceConfigManagement::DeviceClassification(struct libinput_device *device, DeviceId deviceId)
{
    CHKPR(device, ERROR_NULL_POINTER);
    uint32_t udevTags = static_cast<int32_t>(libinput_device_get_tags(device));
    if (udevTags & (EVDEV_UDEV_TAG_MOUSE |
                    EVDEV_UDEV_TAG_TRACKBALL |
                    EVDEV_UDEV_TAG_POINTINGSTICK |
                    EVDEV_UDEV_TAG_TOUCHPAD |
                    EVDEV_UDEV_TAG_TABLET_PAD)) {
        return DeviceConfiguration(device, deviceId);
    }
    MMI_HILOGE("Device config set failed");
    return RET_ERR;
}

int32_t DeviceConfigManagement::OnDeviceAdd(struct libinput_device *device)
{
    CALL_DEBUG_ENTER;
    CHKPR(device, ERROR_NULL_POINTER);
    int32_t deviceId = InputDevMgr->FindInputDeviceId(device);
    if (deviceId == INVALID_DEVICE_ID) {
        MMI_HILOGE("Find device failed");
        return RET_ERR;
    }
    return DeviceClassification(device, deviceId);
}

void DeviceConfigManagement::OnDeviceRemove(struct libinput_device *device)
{
    CALL_DEBUG_ENTER;
    CHKPV(device);
    int32_t deviceId = InputDevMgr->FindInputDeviceId(device);
    auto iter = deviceConfigs_.find(deviceId);
    if (iter == deviceConfigs_.end()) {
        MMI_HILOGE("Device config file remove failed");
        return;
    }
    MouseEventHdr->RemovePointerSpeed(deviceId);
    deviceConfigs_.erase(iter);
}
} // namespace MMI
} // namespace OHOS