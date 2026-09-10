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

#include "key_press_command.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <thread>

#include "input_manager.h"
#include "modifier.h"
#include "option_parser.h"
#include "printer.h"

namespace OHOS::MMI::InputCli {
namespace {
constexpr size_t MAX_PRESSED_KEYS = 5;
constexpr int32_t MAX_HOLD_DURATION_MS = 10000;
constexpr int32_t DEFAULT_HOLD_DURATION_MS = 100;

struct KeyPressOptions {
    int32_t key { 0 };
    int32_t holdDuration { 100 };
    std::vector<int32_t> modifiers;
};

const std::set<std::string> ALLOWED_OPTIONS = {
    "--key",
    "--holdDuration",
    "--modifier",
};

bool ParseKeyPressOptions(const std::vector<std::string> &args, KeyPressOptions &result, std::string &error,
    std::string &suggestion)
{
    Options options;
    if (!ParseOptionPairs(args, ALLOWED_OPTIONS, options)) {
        error = "options must use documented --name value once";
        suggestion = "Please use key press --help";
        return false;
    }
    const NumberRule keyRule {
        .optionName = "--key",
        .isRequired = true,
        .minValue = 1,
        .maxValue = INT32_MAX,
        .outOfRangeMessage = "key must be an integer >= 1",
    };

    if (!ParseNumber(options, keyRule, result.key, error)) {
        suggestion = "Please provide --key <OHOS key code>";
        return false;
    }
    const NumberRule holdRule {
        .optionName = "--holdDuration",
        .isRequired = false,
        .defaultValue = DEFAULT_HOLD_DURATION_MS,
        .minValue = 0,
        .maxValue = MAX_HOLD_DURATION_MS,
        .outOfRangeMessage = "holdDuration is out of range",
    };
    if (!ParseNumber(options, holdRule, result.holdDuration, error)) {
        suggestion = "Please use holdDuration in [0,10000]";
        return false;
    }
    const auto modifier = options.find("--modifier");
    if (modifier != options.end() && !ParseModifiers(modifier->second, result.modifiers, error)) {
        suggestion = "Please use distinct modifier keys";
        return false;
    }
    if (std::find(result.modifiers.begin(), result.modifiers.end(), result.key) != result.modifiers.end()) {
        error = "key must not duplicate a modifier key";
        suggestion = "Please use a key different from modifier keys";
        return false;
    }
    return true;
}
} // namespace

std::string KeyPressCommand::GetDevice() const
{
    return "key";
}

std::string KeyPressCommand::GetName() const
{
    return "press";
}

std::string KeyPressCommand::GetDescription() const
{
    return "Simulate a key press";
}

std::string KeyPressCommand::GetTitle() const
{
    return "Simulate a key press with specified duration";
}

std::string KeyPressCommand::GetUsage() const
{
    return "ohos-input key press [options]";
}

std::vector<ParameterDoc> KeyPressCommand::GetParameters() const
{
    return {
        { "--key <number>", "Key code to press (required, range: >=1, refer to OHOS key code definitions)" },
        { "--holdDuration <number>",
            "Duration to hold the key in ms\n(optional, range: [0, 10000], 0 means instant release, default: 100)" },
        { "--modifier <keys>",
            "Modifier keys, pipe-separated, in press order (optional, e.g. ctrl|shift, no duplicates)" },
    };
}

std::vector<std::string> KeyPressCommand::GetExamples() const
{
    return {
        "# Press Enter key (hold 100ms)",
        "ohos-input key press --key 2054",
        "",
        "# Press A key for 200ms",
        "ohos-input key press --key 2049 --holdDuration 200",
        "",
        "# Ctrl+A (select all)",
        "ohos-input key press --key 2049 --modifier ctrl",
        "",
        "# Ctrl+Shift+S (save as), pressed in order: ctrl then shift; released: shift then ctrl",
        "ohos-input key press --key 2066 --modifier ctrl|shift",
    };
}

int32_t KeyPressCommand::Execute(const std::vector<std::string> &args)
{
    KeyPressOptions options;
    std::string error;
    std::string suggestion;
    if (!ParseKeyPressOptions(args, options, error, suggestion)) {
        return ParameterError(error, suggestion);
    }
    if (options.modifiers.size() + 1 > MAX_PRESSED_KEYS) {
        return ParameterError("no more than 5 keys may be pressed", "Please reduce modifier keys");
    }
    std::shared_ptr<KeyboardControllerImpl> keyboard;
    int32_t ret = InputManager::GetInstance()->CreateKeyboardController(keyboard);
    if (ret != 0 || keyboard == nullptr) {
        return HandleControllerError(ret, "CreateKeyboardController");
    }
    ret = PressModifiers(keyboard, options.modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "PressKey");
    }
    ret = keyboard->PressKey(options.key);
    if (ret != 0) {
        return HandleControllerError(ret, "PressKey");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(options.holdDuration));
    ret = keyboard->ReleaseKey(options.key);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseKey");
    }
    ret = ReleaseModifiers(keyboard, options.modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseKey");
    }
    return OutputPrinter::PrintSuccess({ { "action", "key press" }, { "key", options.key } });
}
} // namespace OHOS::MMI::InputCli
