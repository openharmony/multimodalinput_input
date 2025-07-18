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

#include "input_device.h"

#include <charconv>
#include <cstring>
#include <sstream>
#include <unistd.h>

#include <fcntl.h>
#include <sys/ioctl.h>

namespace OHOS {
namespace MMI {
namespace {
constexpr char DEVICE_PREFIX[] = "DEVICE:";
constexpr char FIELD_SEPARATOR = '|';
constexpr int32_t MAX_DEVICE_NAME = 128;
constexpr int32_t UINT_BIT_COUNT = 8;
constexpr int32_t DEVICE_DESCRIPTION_FILED_COUNT = 4;
}

InputDevice::InputDevice() : id_(0), fd_(-1)
{
}

InputDevice::InputDevice(const std::string& path, uint32_t id)
    : path_(path), id_(id), fd_(-1)
{
    OpenDevice(O_RDONLY | O_NONBLOCK);
    if (fd_ >= 0) {
        QueryDeviceInfo();
    }
}

InputDevice::InputDevice(InputDevice&& other) noexcept
    : path_(std::move(other.path_)),
      name_(std::move(other.name_)),
      hash_(std::move(other.hash_)),
      id_(other.id_),
      fd_(other.fd_)
{
    other.fd_ = -1;
}

InputDevice::~InputDevice()
{
    Close();
}

InputDevice& InputDevice::operator=(InputDevice&& other) noexcept
{
    if (this != &other) {
        Close();
        path_ = std::move(other.path_);
        name_ = std::move(other.name_);
        hash_ = std::move(other.hash_);
        id_ = other.id_;
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

bool InputDevice::IsOpen() const
{
    return fd_ >= 0;
}

void InputDevice::Close()
{
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool InputDevice::OpenForReading()
{
    return OpenDevice(O_RDONLY | O_NONBLOCK);
}

bool InputDevice::OpenForWriting()
{
    if (!VerifyDeviceMatch()) {
        return false;
    }
    return OpenDevice(O_WRONLY);
}

int32_t InputDevice::GetFd() const
{
    return fd_;
}

const std::string& InputDevice::GetPath() const
{
    return path_;
}

const std::string& InputDevice::GetName() const
{
    return name_;
}

uint32_t InputDevice::GetId() const
{
    return id_;
}

std::string InputDevice::GetHash() const
{
    return hash_;
}

void InputDevice::SetId(uint32_t id)
{
    id_ = id;
}

void InputDevice::SetPath(const std::string& path)
{
    path_ = path;
}

void InputDevice::SetName(const std::string& name)
{
    name_ = name;
}

bool InputDevice::ReadEvent(input_event& event)
{
    if (fd_ < 0) {
        return false;
    }
    ssize_t bytesRead = read(fd_, &event, sizeof(event));
    return bytesRead == sizeof(event);
}

bool InputDevice::WriteEvents(const std::vector<input_event>& events)
{
    if (fd_ < 0 || events.empty()) {
        return false;
    }
    ssize_t eventBytes = static_cast<ssize_t>(sizeof(input_event) * events.size());
    ssize_t bytesWritten = write(fd_, &events[0], eventBytes);
    return bytesWritten == eventBytes;
}

bool InputDevice::VerifyDeviceMatch() const
{
    if (name_.empty()) {
        return true;
    }

    // ensure the out coming path safe
    char resolvedPath[PATH_MAX] = {};
    if (realpath(path_.c_str(), resolvedPath) == nullptr) {
        PrintError("Realpath failed. path:%{private}s", path_.c_str());
        return false;
    }

    int32_t tempFd = ::open(resolvedPath, O_RDONLY | O_NONBLOCK);
    if (tempFd < 0) {
        PrintWarning("Cannot verify device %s: %s", path_.c_str(), strerror(errno));
        return true;
    }
    bool matches = false;
    char currentDeviceName[MAX_DEVICE_NAME] = "Unknown";
    if (ioctl(tempFd, EVIOCGNAME(sizeof(currentDeviceName)), currentDeviceName) >= 0) {
        if (name_ == currentDeviceName) {
            matches = true;
        } else {
            PrintError("Device name mismatch for %s: expected '%s' but got '%s'",
                path_.c_str(), name_.c_str(), currentDeviceName);
        }
    } else {
        PrintWarning("Could not get device name for verification: %s", strerror(errno));
        matches = true;
    }
    ::close(tempFd);
    return matches;
}

bool InputDevice::OpenDevice(int32_t flags)
{
    Close();  // Close if already open

    // ensure the out coming path safe
    char resolvedPath[PATH_MAX] = {};
    if (realpath(path_.c_str(), resolvedPath) == nullptr) {
        PrintError("Realpath failed. path:%{private}s", path_.c_str());
        return false;
    }

    fd_ = ::open(realpath, flags);
    if (fd_ < 0) {
        PrintError("Failed to open device %s: %s", path_.c_str(), strerror(errno));
        return false;
    }
    return true;
}

void InputDevice::QueryDeviceInfo()
{
    char name[MAX_DEVICE_NAME] = "Unknown";
    if (ioctl(fd_, EVIOCGNAME(sizeof(name)), name) >= 0) {
        name_ = name;
    }
    CalculateDeviceHash();
}

void InputDevice::CalculateDeviceHash()
{
    std::ostringstream hashInput;
    hashInput << "Name:" << name_ << "|";
    struct input_id device_id;
    if (ioctl(fd_, EVIOCGID, &device_id) >= 0) {
        hashInput << "BusType:" << std::hex << device_id.bustype << "|"
                   << "Vendor:" << std::hex << device_id.vendor << "|"
                   << "Product:" << std::hex << device_id.product << "|"
                   << "Version:" << std::hex << device_id.version << "|";
    }
    unsigned long eventBits[EV_MAX/UINT_BIT_COUNT + 1] = {0};
    if (ioctl(fd_, EVIOCGBIT(0, sizeof(eventBits)), eventBits) >= 0) {
        hashInput << "Events:";
        for (int i = 0; i <= EV_MAX; i++) {
            if (eventBits[i / UINT_BIT_COUNT] & (1UL << (i % UINT_BIT_COUNT))) {
                hashInput << std::hex << i << ",";
            }
        }
    }
    std::string hashStr = hashInput.str();
    if (hashStr.back() == ',') {
        hashStr.pop_back();
    }
    hash_ = std::to_string(std::hash<std::string>{}(hashStr));
}

bool InputDevice::InitFromTextLine(const std::string& line)
{
    std::string workLine = line;
    if (!RemovePrefix(workLine, DEVICE_PREFIX)) {
        PrintError("Invalid device line format: %s", line.c_str());
        return false;
    }
    std::vector<std::string> fields;
    size_t pos = 0;
    while ((pos = workLine.find(FIELD_SEPARATOR)) != std::string::npos) {
        fields.push_back(workLine.substr(0, pos));
        workLine.erase(0, pos + 1);
    }
    fields.push_back(workLine);
    if (fields.size() != DEVICE_DESCRIPTION_FILED_COUNT) {
        PrintError("Device line must have exactly 4 fields: %s", line.c_str());
        return false;
    }
    int32_t index = -1;
    TrimString(fields[++index]);
    uint32_t deviceId;
    auto result = std::from_chars(fields[index].data(), fields[index].data() + fields[index].size(), deviceId);
    if (result.ec != std::errc()) {
        PrintError("Invalid device ID: %s", fields[0].c_str());
        return false;
    }
    TrimString(fields[++index]);
    std::string devicePath = fields[index];
    TrimString(fields[++index]);
    std::string deviceName = fields[index];
    TrimString(fields[++index]);
    std::string deviceHash  = fields[index];
    id_ = deviceId;
    path_ = devicePath;
    name_ = deviceName;
    hash_ = deviceHash;
    return true;
}
} // namespace MMI
} // namespace OHOS