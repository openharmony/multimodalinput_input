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

#include "event_recorder.h"

#include <algorithm>
#include <iostream>
#include <unistd.h>
#include <string>

#include <sys/select.h>

#include "event_utils.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr suseconds_t TIME_OUT = 100000;
}
EventRecorder::EventRecorder(const std::string& outputPath)
    : outputPath_(outputPath), running_(false)
{
}

EventRecorder::~EventRecorder()
{
    Stop();
}

bool EventRecorder::Start(std::vector<InputDevice>& devices)
{
    if (running_) {
        return false;
    }
    if (devices.empty()) {
        PrintError("No devices to record from");
        return false;
    }
    outputFile_.open(outputPath_, std::ios::binary | std::ios::trunc);
    if (!outputFile_) {
        PrintError("Failed to open output file: %s", outputPath_.c_str());
        return false;
    }
    devices_.clear();
    deviceEventBuffers_.clear();
    for (InputDevice& device : devices) {
        PrintInfo("Recording from device %u: %s (%s)",
            device.GetId(), device.GetPath().c_str(), device.GetName().c_str());
        if (!device.IsOpen() && !device.OpenForReading()) {
            PrintError("Failed to open device for reading: %s", device.GetPath().c_str());
            continue;
        }
        devices_.push_back(std::move(device));
    }
    bool hasValidDevices = false;
    for (const auto& device : devices_) {
        if (device.IsOpen()) {
            hasValidDevices = true;
            break;
        }
    }
    if (!hasValidDevices) {
        PrintError("No devices could be opened for recording");
        outputFile_.close();
        return false;
    }
    running_ = true;
    outputFile_ << "EVENTS_BEGIN" << std::endl;
    MainLoop();
    return true;
}

void EventRecorder::Stop()
{
    if (!running_) {
        return;
    }
    running_ = false;
    if (outputFile_.is_open()) {
        outputFile_ << "EVENTS_END" << std::endl<<std::endl;
        outputFile_ << "DEVICES: " << deviceEventBuffers_.size() << std::endl;
        std::cout << "DEVICES: " << deviceEventBuffers_.size() << std::endl;
        for (const auto& device : devices_) {
            if (deviceEventBuffers_.find(device.GetId()) != deviceEventBuffers_.end()) {
                std::string deviceName = device.GetName();
                std::replace(deviceName.begin(), deviceName.end(), '|', '_');
                outputFile_ << "DEVICE: " << device.GetId() << "|" << device.GetPath() << "|" << deviceName << "|";
                outputFile_ << device.GetHash() << std::endl;
                std::cout << "DEVICE: " << device.GetId() << "|" << device.GetPath() << "|" << deviceName << "|";
                std::cout << device.GetHash() << std::endl;
            }
        }
        outputFile_.close();
    }
    devices_.clear();
    deviceEventBuffers_.clear();
    PrintInfo("Recording stopped");
}

void EventRecorder::ProcessDeviceEvents(fd_set& readFds)
{
    for (InputDevice& device : devices_) {
        if (!device.IsOpen()) {
            continue;
        }
        int32_t fd = device.GetFd();
        if (FD_ISSET(fd, &readFds)) {
            input_event event;
            if (device.ReadEvent(event)) {
                EventRecord record;
                record.deviceId = device.GetId();
                record.event = event;
                auto& currentDeviceBuffer = deviceEventBuffers_[record.deviceId];
                currentDeviceBuffer.push_back(record);
                FlushDeviceEvents(record);
            }
        }
    }
}

void EventRecorder::MainLoop()
{
    fd_set readFds;
    struct timeval timeout;
    PrintDebug("Started event recording main loop");
    PrintInfo("Recording started. Press Ctrl+C to stop.");
    while (running_ && !g_shutdown.load()) {
        FD_ZERO(&readFds);
        int32_t maxFd = -1;
        for (const auto& device : devices_) {
            if (device.IsOpen()) {
                int32_t fd = device.GetFd();
                FD_SET(fd, &readFds);
                maxFd = std::max(maxFd, fd);
            }
        }
        if (maxFd < 0) {
            PrintError("No valid devices to monitor");
            break;
        }
        timeout.tv_sec = 0;
        timeout.tv_usec = TIME_OUT;  // 100ms timeout
        int32_t result = select(maxFd + 1, &readFds, nullptr, nullptr, &timeout);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            PrintError("Select error: %d", errno);
            break;
        }
        if (result > 0) {
            ProcessDeviceEvents(readFds);
        }
    }
    PrintDebug("Stopped event recording main loop");
}

void EventRecorder::FlushDeviceEvents(const EventRecord& record)
{
    if (record.event.type != EV_SYN || record.event.code != SYN_REPORT) {
        return;
    }
    auto& currentDeviceBuffer = deviceEventBuffers_[record.deviceId];
    for (const auto& record : currentDeviceBuffer) {
        WriteEventText(record);
    }
    std::cout << std::endl;
    currentDeviceBuffer.clear();
}

void EventRecorder::WriteEventText(const EventRecord& record)
{
    struct input_event event = record.event;
    std::string typeStr = GetEventTypeString(event.type);
    std::string codeStr = GetEventCodeString(event.type, event.code);
    outputFile_ << "["
             << record.deviceId << ", "
             << event.type << ", "
             << event.code << ", "
             << event.value<<", "
             << event.input_event_sec << ", "
             << event.input_event_usec
             << "] # " << typeStr << " / " << codeStr << " " << event.value
             << std::endl;
    std::cout << "["
             << record.deviceId << ", "
             << event.type << ", "
             << event.code << ", "
             << event.value << ", "
             << event.input_event_sec << ", "
             << event.input_event_usec
             << "] # " << typeStr << " / " << codeStr << " " << event.value
             << std::endl;
}

std::string EventRecorder::GetEventTypeString(uint16_t type)
{
    auto it = EVENT_TYPE_MAP.find(type);
    if (it != EVENT_TYPE_MAP.end()) {
        return it->second;
    }
    return "UNKNOWN_TYPE(" + std::to_string(type) + ")";
}

std::string EventRecorder::GetSecondaryEventCodeString(uint16_t type, uint16_t code)
{
    switch (type) {
        case EV_LED: {
            auto it = LED_CODE_MAP.find(code);
            if (it != LED_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
        case EV_REP: {
            auto it = REP_CODE_MAP.find(code);
            if (it != REP_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
        case EV_SND: {
            auto it = SND_CODE_MAP.find(code);
            if (it != SND_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
        case EV_MSC: {
            auto it = MSC_CODE_MAP.find(code);
            if (it != MSC_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
        case EV_SW: {
            auto it = SW_CODE_MAP.find(code);
            if (it != SW_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
    }
    return "";
}

std::string EventRecorder::GetEventCodeString(uint16_t type, uint16_t code)
{
    switch (type) {
        case EV_SYN: {
            auto it = SYN_CODE_MAP.find(code);
            if (it != SYN_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
        case EV_KEY: {
            auto it = KEY_CODE_MAP.find(code);
            if (it != KEY_CODE_MAP.end()) {
                return it->second;
            }
            if (code >= KEY_A && code <= KEY_Z) {
                return "KEY_" + std::string(1, 'A' + (code - KEY_A));
            }
            break;
        }
        case EV_REL: {
            auto it = REL_CODE_MAP.find(code);
            if (it != REL_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
        case EV_ABS: {
            auto it = ABS_CODE_MAP.find(code);
            if (it != ABS_CODE_MAP.end()) {
                return it->second;
            }
            break;
        }
    }
    std::string secondaryResult = GetSecondaryEventCodeString(type, code);
    if (!secondaryResult.empty()) {
        return secondaryResult;
    }
    return "CODE(" + std::to_string(code) + ")";
}
} // namespace MMI
} // namespace OHOS