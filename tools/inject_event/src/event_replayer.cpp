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

#include "event_replayer.h"

#include <charconv>
#include <chrono>
#include <fstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include "common.h"
#include "device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MICROSECONDS_PER_SECOND = 1000000;
const char* DEVICES_PREFIX = "DEVICES:";
const char* EVENTS_BEGIN = "EVENTS_BEGIN";
const char* EVENTS_END = "EVENTS_END";
constexpr char FIELD_COMMA = ',';
constexpr char COMMENT_CHAR = '#';
constexpr char BRACKET_START = '[';
constexpr char BRACKET_END = ']';
}

EventReplayer::EventReplayer(const std::string& inputPath, const std::map<uint16_t, uint16_t>& deviceMapping)
    : inputPath_(inputPath), lastSec_(0), lastUsec_(0), firstEvent_(true)
{
    for (const auto &[sourceId, targetId] : deviceMapping) {
        deviceMapping_[sourceId] = "/dev/input/event" + std::to_string(targetId);
    }
    DeviceManager deviceManager;
    auto devices = deviceManager.DiscoverDevices();
    for (const InputDevice& device : devices) {
        hashToDevicePath_[device.GetHash()] = device.GetPath();
    }
    if (devices.size() != hashToDevicePath_.size()) {
        PrintWarning("Device hashVal is not unique!");
    }
}

bool EventReplayer::SeekToDevicesSection(std::ifstream& inputFile)
{
    if (!inputFile.good()) {
        PrintError("File stream is not in good state");
        return false;
    }
    inputFile.seekg(0, std::ios::end);
    std::streampos fileSize = inputFile.tellg();
    constexpr std::streamoff SEARCH_OFFSET = 2048;
    if (fileSize <= SEARCH_OFFSET) {
        inputFile.seekg(0, std::ios::beg);
    } else {
        inputFile.seekg(-SEARCH_OFFSET, std::ios::end);
        std::string discardLine;
        std::getline(inputFile, discardLine);
        if (inputFile.eof()) {
            inputFile.clear();
            inputFile.seekg(0, std::ios::beg);
        }
    }
    std::string line;
    while (std::getline(inputFile, line)) {
        if (line.find(DEVICES_PREFIX) == 0) {
            inputFile.seekg(-static_cast<std::streamoff>(line.length() + 1), std::ios::cur);
            if (inputFile.peek() == '\r') {
                inputFile.seekg(-1, std::ios::cur);
            }
            return true;
        }
    }
    PrintWarning("DEVICES section not found in file");
    return false;
}

bool EventReplayer::SeekToEventsSection(std::ifstream& inputFile)
{
    if (!inputFile.good()) {
        PrintError("File stream is not in good state");
        return false;
    }
    inputFile.seekg(0, std::ios::beg);
    std::string line;
    while (std::getline(inputFile, line)) {
        if (line == EVENTS_BEGIN) {
            return true;
        }
    }
    return false;
}

bool EventReplayer::Replay()
{
    std::ifstream inputFile(inputPath_);
    if (!SeekToDevicesSection(inputFile)) {
        PrintError("seek to DEVICES_PREFIX tag error");
        return false;
    }
    std::map<uint32_t, std::unique_ptr<InputDevice>> outputDevices;
    if (!InitializeOutputDevices(inputFile, outputDevices)) {
        return false;
    }
    if (outputDevices.empty()) {
        PrintError("No output devices available for replay");
        return false;
    }
    PrintInfo("Starting replay...");
    firstEvent_ = true;
    bool result = ReplayEvents(inputFile, outputDevices);
    PrintInfo(result ? "Replay completed" : "Replay interrupted");
    return true;
}

bool EventReplayer::ProcessDeviceLines(std::ifstream& inputFile,
    std::map<uint32_t, std::unique_ptr<InputDevice>>& outputDevices, uint32_t deviceCount)
{
    std::string line;
    for (uint32_t i = 0; i < deviceCount; i++) {
        line.clear();
        if (!std::getline(inputFile, line)) {
            PrintWarning("Reached end of file after reading %u of %u devices", i, deviceCount);
            break;
        }
        if (line.empty() || line[0] == COMMENT_CHAR) {
            --i;
            continue;
        }
        auto device = std::make_unique<InputDevice>();
        if (!device) {
            PrintError("Failed to allocate device object");
            return false;
        }
        if (!device->InitFromTextLine(line)) {
            PrintWarning("Failed to parse device line: %s", line.c_str());
            continue;
        }
        uint16_t deviceId = static_cast<uint16_t>(device->GetId());
        auto mappingIt = deviceMapping_.find(deviceId);
        if (mappingIt != deviceMapping_.end()) {
            PrintInfo("Mapping device %u to %s", deviceId, mappingIt->second.c_str());
            device->SetPath(mappingIt->second);
        }
        if (deviceMapping_.empty()) {
            std::string path = device->GetPath();
            std::string hash = device->GetHash();
            auto hashIt = hashToDevicePath_.find(hash);
            if (hashIt != hashToDevicePath_.end() && hashToDevicePath_[hash] != path) {
                PrintInfo("Validate and correct path using hash verification");
                device->SetPath(hashToDevicePath_[hash]);
            }
        }
        if (device->OpenForWriting()) {
            PrintInfo("Using device %u: %s", device->GetId(), device->GetName().c_str());
            outputDevices[device->GetId()] = std::move(device);
        } else {
            PrintWarning("Failed to open device for replay: %s", device->GetPath().c_str());
        }
    }
    return true;
}

bool EventReplayer::InitializeOutputDevices(std::ifstream& inputFile,
    std::map<uint32_t, std::unique_ptr<InputDevice>>& outputDevices)
{
    outputDevices.clear();
    std::string line;
    if (!std::getline(inputFile, line)) {
        PrintError("Failed to read device count line");
        return false;
    }
    std::string countStr = line;
    if (!RemovePrefix(countStr, DEVICES_PREFIX)) {
        PrintError("Invalid device count line format");
        return false;
    }
    TrimString(countStr);
    uint32_t deviceCount = 0;
    auto result = std::from_chars(countStr.data(), countStr.data() + countStr.size(), deviceCount);
    if (result.ec != std::errc()) {
        PrintError("Failed to parse device count: %s", countStr.c_str());
        return false;
    }
    PrintInfo("Found %u devices", deviceCount);
    return ProcessDeviceLines(inputFile, outputDevices, deviceCount);
}

void EventReplayer::ApplyEventDelay(const struct input_event& currentEvent)
{
    if (!firstEvent_) {
        unsigned long nowSec = currentEvent.input_event_sec;
        unsigned long nowUsec = currentEvent.input_event_usec;
        long diffSec = nowSec - lastSec_;
        long diffUsec = nowUsec - lastUsec_;
        if (diffUsec < 0) {
            diffSec--;
            diffUsec += MICROSECONDS_PER_SECOND;
        }
        if (diffSec > 0 || diffUsec > 0) {
            std::this_thread::sleep_for(
                std::chrono::seconds(diffSec) + std::chrono::microseconds(diffUsec));
        }
    }
    firstEvent_ = false;
    lastSec_ = currentEvent.input_event_sec;
    lastUsec_ = currentEvent.input_event_usec;
}

bool EventReplayer::ReplayEvents(std::ifstream& inputFile,
    const std::map<uint32_t, std::unique_ptr<InputDevice>>& outputDevices)
{
    if (!SeekToEventsSection(inputFile)) {
        PrintError("Failed to locate events section");
        return false;
    }
    deviceEventBuffers_.clear();
    std::string line;
    while (std::getline(inputFile, line)) {
        if (!inputFile || inputFile.eof()) {
            PrintWarning("Error reading event record");
            return false;
        }
        if (line.empty()) {
            continue;
        }
        if (line == EVENTS_END) {
            PrintDebug("Reached end of events section");
            break;
        }
        uint32_t deviceId;
        input_event event;
        if (!ParseInputLine(line, deviceId, event)) {
            PrintError("Failed to parse event line: %s", line.c_str());
            return false;
        }
        auto deviceIt = outputDevices.find(deviceId);
        if (deviceIt == outputDevices.end()) {
            continue;
        }
        ApplyEventDelay(event);
        auto& currentDeviceBuffer = deviceEventBuffers_[deviceId];
        currentDeviceBuffer.push_back(event);
        if (event.type == EV_SYN && event.code == SYN_REPORT) {
            if (!deviceIt->second->WriteEvents(currentDeviceBuffer)) {
                PrintError("Failed to write events for device %u", deviceId);
                return false;
            }
            currentDeviceBuffer.clear();
        }
        if (g_shutdown.load()) {
            return false;
        }
        line.clear();
    }
    return true;
}

template<typename T>
static bool ParseField(const char*& ptr, const char* endPtr, T& value)
{
    while (ptr < endPtr && (*ptr == ' ' || *ptr == '\t')) {
        ptr++;
    }
    auto result = std::from_chars(ptr, endPtr, value);
    if (result.ec != std::errc()) {
        return false;
    }
    ptr = result.ptr;
    if (ptr >= endPtr) {
        return false;
    }
    if (*ptr++ != FIELD_COMMA) {
        return false;
    }
    return true;
}

bool EventReplayer::ParseInputLine(const std::string& line, uint32_t& deviceId, struct input_event& evt)
{
    size_t commentPos = line.find(COMMENT_CHAR);
    std::string content = (commentPos != std::string::npos) ? line.substr(0, commentPos) : line;
    size_t startPos = content.find(BRACKET_START);
    size_t endPos = content.find(BRACKET_END);
    if (startPos == std::string::npos || endPos == std::string::npos || startPos >= endPos) {
        return false;
    }
    std::string data = content.substr(startPos + 1, endPos - startPos - 1);
    const char* ptr = data.c_str();
    const char* endPtr = ptr + data.length();
    if (!ParseField(ptr, endPtr, deviceId)) {
        return false;
    }
    uint16_t type;
    if (!ParseField(ptr, endPtr, type)) {
        return false;
    }
    evt.type = type;
    uint16_t code;
    if (!ParseField(ptr, endPtr, code)) {
        return false;
    }
    evt.code = code;
    int32_t value;
    if (!ParseField(ptr, endPtr, value)) {
        return false;
    }
    evt.value = value;
    long s;
    if (!ParseField(ptr, endPtr, s)) {
        return false;
    }
    evt.input_event_sec = s;
    long us;
    while (ptr < endPtr && (*ptr == ' ' || *ptr == '\t')) {
        ptr++;
    }
    auto result = std::from_chars(ptr, endPtr, us);
    if (result.ec != std::errc()) {
        return false;
    }
    evt.input_event_usec = us;
    return true;
}
} // namespace MMI
} // namespace OHOS