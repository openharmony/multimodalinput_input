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

#include "mouse_double_click_command.h"

#include <chrono>
#include <cstdint>
#include <set>
#include <thread>

#include "modifier.h"
#include "mouse_support.h"
#include "option_parser.h"
#include "printer.h"

namespace OHOS::MMI::InputCli {
namespace {
constexpr int32_t DEFAULT_CLICK_INTERVAL_MS = 250;
constexpr int32_t MIN_CLICK_INTERVAL_MS = 100;
constexpr int32_t MAX_CLICK_INTERVAL_MS = 400;

const std::set<std::string> ALLOWED_OPTIONS = {
    "--displayId",
    "--x",
    "--y",
    "--button",
    "--holdDuration",
    "--clickInterval",
    "--modifier",
};
} // namespace

std::string MouseDoubleClickCommand::GetName() const
{
    return "mouse-double-click";
}

std::string MouseDoubleClickCommand::GetDescription() const
{
    return "Simulate a mouse double-click";
}

std::string MouseDoubleClickCommand::GetTitle() const
{
    return "Simulate a mouse double-click at specified position";
}

std::string MouseDoubleClickCommand::GetUsage() const
{
    return "ohos-input mouse-double-click [options]";
}

std::vector<ParameterDoc> MouseDoubleClickCommand::GetParameters() const
{
    return {
        { "--displayId <number>", "Display ID (optional, range: >=0, default: 0)" },
        { "--x <integer>", "Target X coordinate (required, range: >=0)" },
        { "--y <integer>", "Target Y coordinate (required, range: >=0)" },
        { "--button <key>",
            "Mouse button to double-click (optional, values: [left, right, middle], default: left)" },
        { "--holdDuration <number>",
            "Duration to hold the button in ms for each click (optional, range: [50, 200], default: 100)" },
        { "--clickInterval <number>",
            "Interval between first press and second press in ms\n(optional, range: [100, 400], "
            "must be greater than holdDuration, default: 250)" },
        { "--modifier <keys>",
            "Modifier keys, pipe-separated, in press order (optional, e.g. ctrl|shift, no duplicates)" },
    };
}

std::vector<std::string> MouseDoubleClickCommand::GetExamples() const
{
    return {
        "# Double-click at position (100, 200)",
        "ohos-input mouse-double-click --x 100 --y 200",
        "",
        "# Right-button double-click with custom interval",
        "ohos-input mouse-double-click --x 100 --y 200 --button right --holdDuration 100 --clickInterval 200",
    };
}

int32_t MouseDoubleClickCommand::Execute(const std::vector<std::string> &args)
{
    Options options;
    std::vector<int32_t> modifiers;
    PointOptions point;
    std::string error;
    const NumberRule clickIntervalRule {
        .optionName = "--clickInterval",
        .isRequired = false,
        .defaultValue = DEFAULT_CLICK_INTERVAL_MS,
        .minValue = MIN_CLICK_INTERVAL_MS,
        .maxValue = MAX_CLICK_INTERVAL_MS,
    };
    if (!ParseMouseOptions(ALLOWED_OPTIONS, args, options, modifiers, error) ||
        !ParsePoint(options, true, point, error) ||
        !ParseNumber(options, clickIntervalRule, point.clickInterval, error)) {
        return ParameterError(error.empty() ? "clickInterval must exceed holdDuration" : error,
            "Please use documented mouse arguments");
    }
    if (point.clickInterval <= point.holdDuration) {
        return ParameterError("clickInterval must exceed holdDuration", "Please use documented mouse arguments");
    }
    MouseSession session;
    int32_t ret = CreateControllers(modifiers, session);
    if (ret != 0) {
        return ret;
    }
    ret = MoveTo(session, point.displayId, point.x, point.y);
    if (ret != 0) {
        return ret;
    }
    ret = PressModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "PressKey");
    }
    ret = ClickButton(session, point);
    if (ret != 0) {
        return ret;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(point.clickInterval - point.holdDuration));
    ret = ClickButton(session, point);
    if (ret != 0) {
        return ret;
    }
    ret = ReleaseModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseKey");
    }
    return OutputPrinter::PrintSuccess({ { "action", "mouse-double-click" }, { "displayId", point.displayId },
        { "x", point.x }, { "y", point.y } });
}
} // namespace OHOS::MMI::InputCli
