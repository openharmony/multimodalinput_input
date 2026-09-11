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

#include "mouse_move_to_command.h"

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
    "--modifier",
};
} // namespace

std::string MouseMoveToCommand::GetDevice() const
{
    return "mouse";
}

std::string MouseMoveToCommand::GetName() const
{
    return "move-to";
}

std::string MouseMoveToCommand::GetDescription() const
{
    return "Move mouse cursor to specified position";
}

std::string MouseMoveToCommand::GetTitle() const
{
    return "Move mouse cursor to specified position";
}

std::string MouseMoveToCommand::GetUsage() const
{
    return "ohos-input mouse move-to [options]";
}

std::vector<ParameterDoc> MouseMoveToCommand::GetParameters() const
{
    return {
        { "--displayId <number>", "Display ID (optional, range: >=0, default: 0)" },
        { "--x <integer>", "Target X coordinate (required, range: >=0)" },
        { "--y <integer>", "Target Y coordinate (required, range: >=0)" },
        { "--modifier <keys>",
            "Modifier keys, pipe-separated, in press order (optional, e.g. ctrl|shift, no duplicates)" },
    };
}

std::vector<std::string> MouseMoveToCommand::GetExamples() const
{
    return {
        "# Move cursor to position (100, 200)",
        "ohos-input mouse move-to --x 100 --y 200",
        "",
        "# Move cursor to display 1",
        "ohos-input mouse move-to --displayId 1 --x 100 --y 200",
        "",
        "# Move with Ctrl held",
        "ohos-input mouse move-to --x 100 --y 200 --modifier ctrl",
    };
}

int32_t MouseMoveToCommand::Execute(const std::vector<std::string> &args)
{
    Options options;
    std::vector<int32_t> modifiers;
    PointOptions point;
    std::string error;
    if (!ParseMouseOptions(ALLOWED_OPTIONS, args, options, modifiers, error) ||
        !ParsePoint(options, false, point, error)) {
        return ParameterError(error.empty() ? "options must use documented --name value once" : error,
            "Please use documented mouse arguments");
    }
    MouseSession session;
    int32_t ret = CreateControllers(modifiers, session);
    if (ret != 0) {
        return ret;
    }
    ret = PressModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "PressKey");
    }
    ret = MoveTo(session, point.displayId, point.x, point.y);
    if (ret != 0) {
        return ret;
    }
    ret = ReleaseModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseKey");
    }
    return OutputPrinter::PrintSuccess({ { "action", "mouse move-to" }, { "displayId", point.displayId },
        { "x", point.x }, { "y", point.y } });
}
} // namespace OHOS::MMI::InputCli
