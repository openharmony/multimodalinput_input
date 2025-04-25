/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "device_manager.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <map>

#include <dirent.h>

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t EVENT_PREFIX_LENGTH = 5;
constexpr const char* EVENT_PREFIX = "event";
constexpr int32_t ID_WIDTH = 5;
constexpr int32_t PATH_WIDTH = 20;
constexpr int32_t TOTAL_WIDTH = 80;
constexpr int32_t INVALID_DEVICE_ID = -1;
constexpr const char* INPUT_DEVICE_DIR = "/dev/input";
}

int32_t DeviceManager::ExtractEventNumber(const std::string& fileName)
{
    if (fileName.length() < EVENT_PREFIX_LENGTH || fileName.substr(0, EVENT_PREFIX_LENGTH) != EVENT_PREFIX) {
        return INVALID_DEVICE_ID;
    }
    std::string numberPart = fileName.substr(EVENT_PREFIX_LENGTH);
    if (!std::all_of(numberPart.begin(), numberPart.end(), ::isdigit)) {
        return INVALID_DEVICE_ID;
    }
    int32_t eventNum;
    auto [ptr, ec] = std::from_chars(numberPart.data(), numberPart.data() + numberPart.size(), eventNum);
    if (ec == std::errc() &&
        ptr == numberPart.data() + numberPart.size() &&
        eventNum >= 0) {
        return eventNum;
    }
    return INVALID_DEVICE_ID;
}

std::string DeviceManager::BuildDevicePath(const std::string& fileName) const
{
    return std::string(INPUT_DEVICE_DIR) + "/" + fileName;
}

std::vector<InputDevice> DeviceManager::DiscoverDevices()
{
    std::vector<InputDevice> devices;
    DIR* dir = opendir(INPUT_DEVICE_DIR);
    if (!dir) {
        PrintError("Cannot open /dev/input directory: %s", strerror(errno));
        return devices;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string fileName(entry->d_name);
        std::string path = BuildDevicePath(entry->d_name);
        int32_t eventNum = ExtractEventNumber(fileName);
        if (eventNum >= 0) {
            InputDevice device(path, static_cast<uint32_t>(eventNum));
            if (device.IsOpen()) {
                devices.push_back(std::move(device));
            }
        }
    }
    closedir(dir);
    std::sort(devices.begin(), devices.end(),
        [](const InputDevice& a, const InputDevice& b) {
            return a.GetId() < b.GetId();
        });
    return devices;
}

void DeviceManager::PrintDeviceList()
{
    auto devices = DiscoverDevices();
    if (devices.empty()) {
        std::cout << "No input devices found." << std::endl;
        return;
    }
    std::cout << "Available input devices:" << std::endl;
    std::cout << std::setw(ID_WIDTH) << "ID" << " | "
              << std::setw(PATH_WIDTH) << "Path" << " | "
              << "Name" << std::endl;
    std::cout << std::string(TOTAL_WIDTH, '-') << std::endl;
    for (const auto& device : devices) {
        std::cout << std::setw(ID_WIDTH) << device.GetId() << " | "
                  << std::setw(PATH_WIDTH) << device.GetPath() << " | "
                  << device.GetName() << std::endl;
    }
}
} // namespace MMI
} // namespace OHOS