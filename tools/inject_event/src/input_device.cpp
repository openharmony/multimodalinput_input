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
#include <unistd.h>

#include <fcntl.h>
#include <sys/ioctl.h>

namespace OHOS {
namespace MMI {
namespace {
constexpr char DEVICE_PREFIX[] = "DEVICE:";
constexpr char FIELD_SEPARATOR = '|';
constexpr int32_t MAX_DEVICE_NAME = 128;
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
    ssize_t eventBytes = sizeof(input_event) * events.size();
    ssize_t bytesWritten = write(fd_, &events[0], eventBytes);
    return bytesWritten == eventBytes;
}

bool InputDevice::VerifyDeviceMatch() const
{
    if (name_.empty()) {
        return true;
    }
    int32_t tempFd = ::open(path_.c_str(), O_RDONLY | O_NONBLOCK);
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
    fd_ = ::open(path_.c_str(), flags);
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
}

bool InputDevice::InitFromTextLine(const std::string& line)
{
    std::string workLine = line;
    if (!RemovePrefix(workLine, DEVICE_PREFIX)) {
        PrintError("Invalid device line format: %s", line.c_str());
        return false;
    }
    size_t firstSep = workLine.find(FIELD_SEPARATOR);
    if (firstSep == std::string::npos) {
        PrintError("Missing first separator in device line: %s", line.c_str());
        return false;
    }
    std::string idStr = workLine.substr(0, firstSep);
    TrimString(idStr);
    uint32_t deviceId = 0;
    auto result = std::from_chars(idStr.data(), idStr.data() + idStr.size(), deviceId);
    if (result.ec != std::errc()) {
        PrintError("Invalid device ID: %s", idStr.c_str());
        return false;
    }
    size_t secondSep = workLine.find(FIELD_SEPARATOR, firstSep + 1);
    if (secondSep == std::string::npos) {
        PrintError("Missing second separator in device line: %s", line.c_str());
        return false;
    }
    std::string path = workLine.substr(firstSep + 1, secondSep - firstSep - 1);
    std::string name = workLine.substr(secondSep + 1);
    TrimString(path);
    TrimString(name);
    id_ = deviceId;
    path_ = path;
    name_ = name;
    return true;
}
} // namespace MMI
} // namespace OHOS