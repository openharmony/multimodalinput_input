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

#include "virtual_device.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <map>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <securec.h>

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t DEFAULT_BUF_SIZE { 1024 };
}

VirtualDevice::VirtualDevice(const std::string &name, uint16_t bustype,
                             uint16_t vendor, uint16_t product)
    : uinputDev_ {
        .id = {
            .bustype = bustype,
            .vendor = vendor,
            .product = product,
            .version = 1
        }
    }
{
    if (strcpy_s(uinputDev_.name, sizeof(uinputDev_.name), name.c_str()) != EOK) {
        std::cout << "Invalid device name:'" << name << "'" << std::endl;
    }
}

VirtualDevice::~VirtualDevice()
{
    Close();
}

void VirtualDevice::SetSupportedEvents()
{
    static const std::map<int32_t, std::function<std::vector<uint32_t>()>> uinputTypes { { UI_SET_EVBIT,
        std::bind(&VirtualDevice::GetEventTypes, this) },
        { UI_SET_KEYBIT, std::bind(&VirtualDevice::GetKeys, this) },
        { UI_SET_PROPBIT, std::bind(&VirtualDevice::GetProperties, this) },
        { UI_SET_ABSBIT, std::bind(&VirtualDevice::GetAbs, this) },
        { UI_SET_RELBIT, std::bind(&VirtualDevice::GetRelBits, this) },
        { UI_SET_MSCBIT, std::bind(&VirtualDevice::GetMiscellaneous, this) },
        { UI_SET_LEDBIT, std::bind(&VirtualDevice::GetLeds, this) },
        { UI_SET_SWBIT, std::bind(&VirtualDevice::GetSwitches, this) },
        { UI_SET_FFBIT, std::bind(&VirtualDevice::GetRepeats, this) } };

    for (const auto &setEvents : uinputTypes) {
        const auto &events = setEvents.second();
        for (const auto &e : events) {
            if (ioctl(fd_, setEvents.first, e) < 0) {
                std::cout << "Failed while setting event type:" << ::strerror(errno) << std::endl;
            }
        }
    }
}

void VirtualDevice::SetAbsResolution()
{
    for (const auto &item : absInit_) {
        if (ioctl(fd_, UI_ABS_SETUP, &item) < 0) {
            std::cout << "Failed while setting abs info:" << ::strerror(errno) << std::endl;
        }
    }
}

void VirtualDevice::SetPhys()
{
    std::string phys;

    static const std::map<std::string, std::string> mapNames {
        { "Virtual Mouse", "mouse" },
        { "Virtual TouchScreen", "touchscreen" },
        { "Virtual Keyboard", "Keyboard" },
    };
    auto tIter = mapNames.find(std::string(uinputDev_.name));
    if (tIter == mapNames.cend()) {
        std::cout << "Unrecognized device name:" << uinputDev_.name << std::endl;
        return;
    }
    phys = tIter->second;
    phys.append("/").append(std::to_string(getpid()));

    if (ioctl(fd_, UI_SET_PHYS, phys.c_str()) < 0) {
        std::cout << "Failed while setting phys:" << ::strerror(errno) << std::endl;
    }
}

void VirtualDevice::SetIdentity()
{
    if (write(fd_, &uinputDev_, sizeof(uinputDev_)) < 0) {
        std::cout << "Unable to set uinput device info:" << ::strerror(errno) << std::endl;
    }
}

bool VirtualDevice::SetUp()
{
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd_ < 0) {
        std::cout << "Unable to open uinput" << std::endl;
        return false;
    }
    std::cout << "uinput opened: " << fd_ << std::endl;
    SetAbsResolution();
    SetPhys();
    SetSupportedEvents();
    SetIdentity();

    if (ioctl(fd_, UI_DEV_CREATE) < 0) {
        std::cout << "Failed to setup uinput device" << std::endl;
        if (::close(fd_) != 0) {
            std::cout << "close error:" << ::strerror(errno) << std::endl;
        }
        fd_ = -1;
        return false;
    }
    return true;
}

void VirtualDevice::Close()
{
    if (fd_ >= 0) {
        if (ioctl(fd_, UI_DEV_DESTROY) < 0) {
            std::cout << "ioctl error:" << ::strerror(errno) << std::endl;
        }
        if (close(fd_) != 0) {
            std::cout << "close error:" << ::strerror(errno) << std::endl;
        }
        fd_ = -1;
    }
}

void VirtualDevice::SetResolution(const ResolutionInfo &resolutionInfo)
{
    uinputAbs_.code = resolutionInfo.axisCode;
    uinputAbs_.absinfo.resolution = resolutionInfo.absResolution;
    absInit_.push_back(uinputAbs_);
}

void VirtualDevice::SetAbsValue(const AbsInfo &absInfo)
{
    uinputDev_.absmin[absInfo.code] = absInfo.minValue;
    uinputDev_.absmax[absInfo.code] = absInfo.maxValue;
    uinputDev_.absfuzz[absInfo.code] = absInfo.fuzz;
    uinputDev_.absflat[absInfo.code] = absInfo.flat;
}

const std::vector<uint32_t> &VirtualDevice::GetEventTypes() const
{
    return eventTypes_;
}

const std::vector<uint32_t> &VirtualDevice::GetKeys() const
{
    return keys_;
}

const std::vector<uint32_t> &VirtualDevice::GetProperties() const
{
    return properties_;
}

const std::vector<uint32_t> &VirtualDevice::GetAbs() const
{
    return abs_;
}

const std::vector<uint32_t> &VirtualDevice::GetRelBits() const
{
    return relBits_;
}

const std::vector<uint32_t> &VirtualDevice::GetLeds() const
{
    return leds_;
}

const std::vector<uint32_t> &VirtualDevice::GetRepeats() const
{
    return repeats_;
}

const std::vector<uint32_t> &VirtualDevice::GetMiscellaneous() const
{
    return miscellaneous_;
}

const std::vector<uint32_t> &VirtualDevice::GetSwitches() const
{
    return switches_;
}

std::string VirtualDevice::GetDevNode() const
{
    char devNode[PATH_MAX] { "/dev/input/" };

    int32_t ret = ::ioctl(fd_, UI_GET_SYSNAME(sizeof(devNode) - strlen(devNode)), &devNode[strlen(devNode)]);
    if (ret == -1) {
        std::cout << "ioctl(" << fd_ << ") fail: " << ::strerror(errno) << std::endl;
        return {};
    }
    return std::string(devNode);
}

bool VirtualDevice::FindDeviceNode(const std::string &name, std::string &node)
{
    std::map<std::string, std::string> nodes;
    GetInputDeviceNodes(nodes);
    std::cout << "There are " << nodes.size() << " device nodes" << std::endl;

    std::map<std::string, std::string>::const_iterator cItr = nodes.find(name);
    if (cItr == nodes.cend()) {
        std::cout << "No virtual stylus were found" << std::endl;
        return false;
    }
    std::cout << "Node name : \'" << cItr->second << "\'" << std::endl;
    std::ostringstream ss;
    ss << "/dev/input/" << cItr->second;
    node = ss.str();
    return true;
}

void VirtualDevice::Execute(std::vector<std::string> &results)
{
    char buffer[DEFAULT_BUF_SIZE] {};
    FILE *pin = popen("cat /proc/bus/input/devices", "r");
    if (pin == nullptr) {
        std::cout << "Failed to popen command" << std::endl;
        return;
    }
    while (!feof(pin)) {
        if (fgets(buffer, sizeof(buffer), pin) != nullptr) {
            results.push_back(buffer);
        }
    }
    pclose(pin);
}

void VirtualDevice::GetInputDeviceNodes(std::map<std::string, std::string> &nodes)
{
    std::vector<std::string> results;
    Execute(results);
    if (results.empty()) {
        std::cout << "Failed to list devices" << std::endl;
        return;
    }
    const std::string kname { "Name=\"" };
    const std::string kevent { "event" };
    std::string name;
    for (const auto &res : results) {
        if (res[0] == 'N') {
            std::string::size_type spos = res.find(kname);
            if (spos != std::string::npos) {
                spos += kname.size();
                std::string::size_type tpos = res.find("\"", spos);
                if (tpos != std::string::npos) {
                    name = res.substr(spos, tpos - spos);
                }
            }
        } else if (!name.empty() && (res[0] == 'H')) {
            std::string::size_type spos = res.find(kevent);
            if (spos != std::string::npos) {
                std::map<std::string, std::string>::const_iterator cItr = nodes.find(name);
                if (cItr != nodes.end()) {
                    nodes.erase(cItr);
                }
                std::string::size_type tpos = spos + kevent.size();
                while (std::isalnum(res[tpos])) {
                    ++tpos;
                }
                auto [_, ret] = nodes.emplace(name, res.substr(spos, tpos - spos));
                if (!ret) {
                    std::cout << "name is duplicated" << std::endl;
                }
                name.clear();
            }
        }
    }
}
} // namespace MMI
} // namespace OHOS