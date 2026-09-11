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

#include "mouse_click_command.h"

#include <cstdint>
#include <set>

#include "modifier.h"
#include "mouse_support.h"
#include "printer.h"

namespace OHOS::MMI::InputCli {
namespace {
const std::set<std::string> ALLOWED_OPTIONS = {
    "--displayId",
    "--x",
    "--y",
    "--button",
    "--holdDuration",
    "--modifier",
};
} // namespace

std::string MouseClickCommand::GetDevice() const
{
    return "mouse";
}

std::string MouseClickCommand::GetName() const
{
    return "click";
}

std::string MouseClickCommand::GetDescription() const
{
    return "Simulate a mouse click";
}

std::string MouseClickCommand::GetTitle() const
{
    return "Simulate a mouse click at specified position";
}

std::string MouseClickCommand::GetUsage() const
{
    return "ohos-input mouse click [options]";
}

std::vector<ParameterDoc> MouseClickCommand::GetParameters() const
{
    return {
        { "--displayId <number>", "Display ID (optional, range: >=0, default: 0)" },
        { "--x <integer>", "Target X coordinate (required, range: >=0)" },
        { "--y <integer>", "Target Y coordinate (required, range: >=0)" },
        { "--button <key>", "Mouse button to click (optional, values: [left, right, middle], default: left)" },
        { "--holdDuration <number>", "Duration to hold the button in ms (optional, range: [50, 200], default: 100)" },
        { "--modifier <keys>",
            "Modifier keys, pipe-separated, in press order (optional, e.g. ctrl|shift, no duplicates)" },
    };
}

std::vector<std::string> MouseClickCommand::GetExamples() const
{
    return {
        "# Click at position (100, 200)",
        "ohos-input mouse click --x 100 --y 200",
        "",
        "# Ctrl+click at position (300, 400) with 100ms hold",
        "ohos-input mouse click --x 300 --y 400 --holdDuration 100 --modifier ctrl",
        "",
        "# Shift+Ctrl+click (pressed in order: shift then ctrl; released: ctrl then shift)",
        "ohos-input mouse click --x 300 --y 400 --modifier shift|ctrl",
    };
}

int32_t MouseClickCommand::Execute(const std::vector<std::string> &args)
{
    Options options;
    std::vector<int32_t> modifiers;
    PointOptions point;
    std::string error;
    if (!ParseMouseOptions(ALLOWED_OPTIONS, args, options, modifiers, error) ||
        !ParsePoint(options, true, point, error)) {
        return ParameterError(error.empty() ? "options must use documented --name value once" : error,
            "Please use documented mouse arguments");
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
    ret = ReleaseModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseKey");
    }
    return OutputPrinter::PrintSuccess({ { "action", "mouse click" }, { "displayId", point.displayId },
        { "x", point.x }, { "y", point.y } });
}
} // namespace OHOS::MMI::InputCli
