/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "executor.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "command.h"
#include "key_press_command.h"
#include "printer.h"

namespace OHOS::MMI::InputCli {
namespace {
const std::string TOP_LEVEL_SUGGESTION = "Please use ohos-input --help";
constexpr size_t OPTION_INDENT_WIDTH = 2;
constexpr size_t OPTION_COLUMN_WIDTH = 24;
constexpr size_t OPTION_GAP_WIDTH = 2;
constexpr size_t DESCRIPTION_COLUMN_WIDTH = OPTION_INDENT_WIDTH + OPTION_COLUMN_WIDTH + OPTION_GAP_WIDTH;

struct DeviceMeta {
    std::string name;
    std::string summary;
    std::vector<std::string> examples;
};

const std::vector<std::shared_ptr<Command>> &CommandTable()
{
    static const std::vector<std::shared_ptr<Command>> commands = {
        std::make_shared<KeyPressCommand>(),
    };
    return commands;
}

const std::vector<DeviceMeta> &DeviceTable()
{
    static const std::vector<DeviceMeta> table = {
        { "key", "Keyboard input simulation operations",
            { "ohos-input key press --key 2054", "ohos-input key press --key 2049 --modifier ctrl" } },
    };
    return table;
}

const DeviceMeta *FindDevice(const std::string &name)
{
    for (const DeviceMeta &device : DeviceTable()) {
        if (name == device.name) {
            return &device;
        }
    }
    return nullptr;
}

std::string StripTrailingNewline(std::ostringstream &stream)
{
    std::string text = stream.str();
    if (!text.empty() && text.back() == '\n') {
        text.pop_back();
    }
    return text;
}

void AppendSummaryLine(std::ostringstream &stream, const std::string &name, const std::string &summary)
{
    stream << "  " << std::left << std::setw(OPTION_COLUMN_WIDTH) << name << "  " << summary << "\n";
}

void AppendDocLine(std::ostringstream &stream, const std::string &name, const std::string &description)
{
    size_t begin = 0;
    bool firstLine = true;
    while (begin <= description.size()) {
        const size_t end = description.find('\n', begin);
        const std::string part = description.substr(begin, end == std::string::npos ? end : end - begin);
        if (firstLine) {
            stream << "  " << std::left << std::setw(OPTION_COLUMN_WIDTH) << name << "  " << part << "\n";
            firstLine = false;
        } else {
            stream << std::string(DESCRIPTION_COLUMN_WIDTH, ' ') << part << "\n";
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
}

void AppendExamples(std::ostringstream &stream, const std::vector<std::string> &examples)
{
    if (examples.empty()) {
        return;
    }
    stream << "Examples:\n";
    for (const auto &example : examples) {
        stream << (example.empty() ? "" : "  ") << example << "\n";
    }
}

std::string BuildGlobalHelp()
{
    std::ostringstream stream;
    stream << "ohos-input - Keyboard and mouse input simulation tool for AI Agent applications\n\n";
    stream << "Usage:\n  ohos-input <device> <action> [options]\n\n";
    stream << "Parameters:\n";
    AppendDocLine(stream, "--help", "Display this help message");
    AppendDocLine(stream, "--version", "Display tool version");
    stream << "\nSubCommands:\n";
    for (const DeviceMeta &device : DeviceTable()) {
        AppendSummaryLine(stream, device.name, device.summary);
    }
    stream << "\n";
    AppendExamples(stream, { "# Key press with Ctrl modifier", "ohos-input key press --key 2049 --modifier ctrl" });
    return StripTrailingNewline(stream);
}

std::string BuildDeviceHelp(const DeviceMeta &device)
{
    std::ostringstream stream;
    stream << "ohos-input " << device.name << " - " << device.summary << "\n\n";
    stream << "Usage:\n  ohos-input " << device.name << " <action> [options]\n\n";
    stream << "SubCommands:\n";
    for (const auto &command : GetCommandsByDevice(device.name)) {
        AppendSummaryLine(stream, command->GetName(), command->GetDescription());
    }
    stream << "\n";
    AppendExamples(stream, device.examples);
    return StripTrailingNewline(stream);
}

std::string BuildCommandHelp(const std::shared_ptr<Command> &command)
{
    std::ostringstream stream;
    stream << "ohos-input " << command->GetDevice() << " " << command->GetName() << " - "
           << command->GetTitle() << "\n\n";
    stream << "Usage:\n  " << command->GetUsage() << "\n\n";
    stream << "Parameters:\n";
    for (const auto &[name, description] : command->GetParameters()) {
        AppendDocLine(stream, name, description);
    }
    AppendDocLine(stream, "--help", "Display this help message");
    stream << "\n";
    AppendExamples(stream, command->GetExamples());
    return StripTrailingNewline(stream);
}
} // namespace

std::shared_ptr<Command> GetCommand(const std::string &device, const std::string &name)
{
    for (const auto &command : CommandTable()) {
        if (command->GetDevice() == device && command->GetName() == name) {
            return command;
        }
    }
    return nullptr;
}

std::vector<std::shared_ptr<Command>> GetCommandsByDevice(const std::string &device)
{
    std::vector<std::shared_ptr<Command>> matched;
    for (const auto &command : CommandTable()) {
        if (command->GetDevice() == device) {
            matched.push_back(command);
        }
    }
    return matched;
}

int32_t ExecuteCommand(const std::vector<std::string> &args)
{
    if (args.empty() || args[0] == "--help") {
        OutputPrinter::PrintHelp(BuildGlobalHelp());
        return 0;
    }
    if (args[0] == "--version") {
        std::cout << OHOS_INPUT_VERSION << std::endl;
        return 0;
    }
    const DeviceMeta *device = FindDevice(args[0]);
    if (device == nullptr) {
        return UnknownCommandError(args[0], TOP_LEVEL_SUGGESTION);
    }
    if (args.size() == 1U || args[1] == "--help") {
        OutputPrinter::PrintHelp(BuildDeviceHelp(*device));
        return 0;
    }
    const auto command = GetCommand(device->name, args[1]);
    if (command == nullptr) {
        return UnknownCommandError(args[1], TOP_LEVEL_SUGGESTION);
    }
    const std::vector<std::string> commandArgs(args.begin() + 2, args.end());
    if (std::find(commandArgs.begin(), commandArgs.end(), "--help") != commandArgs.end()) {
        OutputPrinter::PrintHelp(BuildCommandHelp(command));
        return 0;
    }
    return command->Execute(commandArgs);
}
} // namespace OHOS::MMI::InputCli
