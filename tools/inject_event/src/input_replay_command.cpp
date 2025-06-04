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

#include "input_replay_command.h"

#include <atomic>
#include <charconv>
#include <cstring>
#include <csignal>
#include <getopt.h>
#include <iostream>
#include <thread>
#include <unistd.h>

#include "common.h"
#include "device_manager.h"
#include "event_recorder.h"
#include "event_replayer.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MIN_ARGC = 2;
}

std::atomic<bool> g_shutdown { false };

InputReplayCommand::InputReplayCommand(int32_t argc, char** argv)
    : argc_(argc), argv_(argv)
{
    programName_ = (argc > 0) ? argv[0] : "uinput";
}

bool InputReplayCommand::ParseOptions()
{
    static struct option longOptions[] = {
        {"help", no_argument, 0, 'h'},
        {"list", no_argument, 0, 'l'},
        {"all", no_argument, 0, 'a'},
        {"map", required_argument, 0, 'm'},
        {0, 0, 0, 0}
    };
    int32_t opt;
    int32_t optionIndex = 0;
    optind = 1;
    while ((opt = getopt_long(argc_, argv_, "hlam:", longOptions, &optionIndex)) != -1) {
        switch (opt) {
            case 'h':
                PrintUsage();
                exit(0);
            case 'l':
                DeviceManager().PrintDeviceList();
                exit(0);
            case 'a':
                useAllDevices_ = true;
                break;
            case 'm':
                if (!ParseDeviceMapping(optarg)) {
                    return false;
                }
                break;
            default:
                return false;
        }
    }
    return true;
}

bool InputReplayCommand::Parse()
{
    if (argc_ < MIN_ARGC) {
        PrintUsage();
        return false;
    }
    if (!ParseOptions()) {
        return false;
    }
    if (optind >= argc_) {
        PrintError("Missing command (record/replay)");
        return false;
    }
    command_ = argv_[optind++];
    if (optind >= argc_) {
        PrintError("Missing file path");
        return false;
    }
    filePath_ = argv_[optind++];
    if (command_ == "record") {
        return ParseRecordCommand();
    } else if (command_ == "replay") {
        return ParseReplayCommand();
    } else {
        PrintError("Invalid command, supported: record/replay");
        return false;
    }
}

inline void SignalHandler(int32_t sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        g_shutdown.store(true);
        std::cout << "\nShutdown signal received, cleaning up..." << std::endl;
    }
}

int32_t InputReplayCommand::HandleRecordReplayCommand(int32_t argc, char** argv)
{
    OHOS::MMI::InputReplayCommand parser(argc, argv);
    if (geteuid() != 0) {
        std::cerr << "Error: This program must be run as root" << std::endl;
        return RET_ERR;
    }
    if (!parser.Parse()) {
        std::cerr << "Failed to parse record/replay command" << std::endl;
        return RET_ERR;
    }

    if (!parser.Execute()) {
        return RET_ERR;
    }
    return RET_OK;
}

bool InputReplayCommand::Execute()
{
    if (command_ == "record") {
        return ExecuteRecordCommand();
    } else if (command_ == "replay") {
        return ExecuteReplayCommand();
    }
    return false;
}

bool InputReplayCommand::ParseDeviceMapping(const std::string& mappingStr)
{
    deviceMapping_.clear();
    const char* ptr = mappingStr.c_str();
    const char* endPtr = ptr + mappingStr.length();
    while (ptr < endPtr) {
        uint16_t key;
        auto keyResult = std::from_chars(ptr, endPtr, key);
        if (keyResult.ec != std::errc() || keyResult.ptr >= endPtr || *keyResult.ptr != ':') {
            return false;
        }
        ptr = keyResult.ptr + 1;
        uint16_t value;
        auto valueResult = std::from_chars(ptr, endPtr, value);
        if (valueResult.ec != std::errc()) {
            return false;
        }
        deviceMapping_[key] = value;
        ptr = valueResult.ptr;
        if (ptr < endPtr) {
            if (*ptr != ',') {
                return false;
            }
            ptr++;
        }
    }
    return !deviceMapping_.empty();
}

void InputReplayCommand::SetupSignalHandlers()
{
    struct sigaction sa;
    sa.sa_handler = SignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

bool InputReplayCommand::ParseRecordCommand()
{
    if (!useAllDevices_) {
        while (optind < argc_) {
            devicePaths_.push_back(argv_[optind++]);
        }
        if (devicePaths_.empty()) {
            PrintError("No devices specified for recording");
            PrintError("Use --all to record from all devices or specify device paths");
            return false;
        }
    }
    if (optind < argc_) {
        PrintError("Unexpected arguments for record command");
        return false;
    }
    return true;
}

bool InputReplayCommand::ParseReplayCommand()
{
    if (useAllDevices_) {
        PrintError("Not use -a option for replay command!");
        return false;
    }
    if (optind < argc_) {
        PrintError("Unexpected arguments for replay command");
        return false;
    }
    return true;
}

bool InputReplayCommand::ExecuteRecordCommand()
{
    std::vector<InputDevice> devices;
    if (useAllDevices_) {
        DeviceManager deviceManager;
        devices = deviceManager.DiscoverDevices();
    } else {
        const std::string PREFIX = "/dev/input/event";
        for (size_t i = 0; i < devicePaths_.size(); i++) {
            const std::string& path = devicePaths_[i];
            if (path.substr(0, PREFIX.length()) != PREFIX) {
                PrintError("Invalid input device path format: %s", path.c_str());
                return false;
            }
            uint16_t deviceId = 0;
            const char* start = path.c_str() + PREFIX.length();
            const char* end = path.c_str() + path.length();
            std::from_chars_result result = std::from_chars(start, end, deviceId);
            if (result.ec != std::errc() || result.ptr != end) {
                PrintError("Invalid device number in path: %s", path.c_str());
                return false;
            }
            InputDevice device(path, deviceId);
            if (device.IsOpen()) {
                devices.push_back(std::move(device));
            } else {
                PrintWarning("Failed to open device: %s", path.c_str());
            }
        }
    }
    if (devices.empty()) {
        PrintError("No valid input devices specified");
        return false;
    }
    SetupSignalHandlers();
    EventRecorder recorder(filePath_);
    if (!recorder.Start(devices)) {
        return false;
    }
    recorder.Stop();
    return true;
}

bool InputReplayCommand::ExecuteReplayCommand()
{
    SetupSignalHandlers();
    PrintInfo("Press Enter to start replay...");
    std::cin.get();
    EventReplayer replayer(filePath_, deviceMapping_);
    return replayer.Replay();
}

void InputReplayCommand::PrintUsage() const
{
    std::cout << "Usage:" << std::endl
              << "  " << programName_ << " [options] record <output-file> [device paths...]" << std::endl
              << "  " << programName_ << " [options] replay <input-file>" << std::endl
              << std::endl
              << "Options:" << std::endl
              << "  -h, --help       Show this help message" << std::endl
              << "  -l, --list       List available input devices" << std::endl
              << "  -a, --all        Record from all available input devices" << std::endl
              << "  -m, --map        Specify device mapping for replay (e.g., \"0:0,1:2,4:2\")" << std::endl
              << "                   Format: sourceDeviceId:targetDeviceId,..." << std::endl
              << std::endl
              << "Examples:" << std::endl
              << "  " << programName_ << " record -a events.bin           # Record from all devices" << std::endl
              << "  " << programName_ << " record events.bin /dev/input/event0 /dev/input/event1  "
                                         "# Record from specific devices" << std::endl
              << "  " << programName_ << " replay events.bin              # Replay to original devices" << std::endl
              << "  " << programName_
              << " replay -m \"0:1,1:0\" events.bin # Replay with custom device mapping" << std::endl;
}
} // namespace MMI
} // namespace OHOS