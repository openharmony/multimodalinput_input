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

#include "mouse_scroll_command.h"

#include <cstdint>
#include <set>

#include "modifier.h"
#include "mouse_support.h"
#include "option_parser.h"
#include "pointer_event.h"
#include "printer.h"

namespace OHOS::MMI::InputCli {
namespace {
constexpr int32_t SCROLL_ANGLE_PER_CLICK = 15;

const std::set<std::string> ALLOWED_OPTIONS = {
    "--clicks",
    "--modifier",
};
} // namespace

std::string MouseScrollCommand::GetName() const
{
    return "mouse-scroll";
}

std::string MouseScrollCommand::GetDescription() const
{
    return "Simulate vertical mouse scroll";
}

std::string MouseScrollCommand::GetTitle() const
{
    return "Simulate vertical mouse scroll";
}

std::string MouseScrollCommand::GetUsage() const
{
    return "ohos-input mouse-scroll [options]";
}

std::vector<ParameterDoc> MouseScrollCommand::GetParameters() const
{
    return {
        { "--clicks <number>",
            "Number of scroll clicks (required, range: [-100, -1] or [1, 100],\npositive for scroll up, "
            "negative for scroll down. 1 click = 15 degrees)" },
        { "--modifier <keys>",
            "Modifier keys, pipe-separated, in press order (optional, e.g. ctrl|shift, no duplicates)" },
    };
}

std::vector<std::string> MouseScrollCommand::GetExamples() const
{
    return {
        "# Scroll down 3 clicks (vertical)",
        "ohos-input mouse-scroll --clicks -3",
        "",
        "# Ctrl+scroll up 5 clicks (vertical)",
        "ohos-input mouse-scroll --clicks 5 --modifier ctrl",
    };
}

int32_t MouseScrollCommand::Execute(const std::vector<std::string> &args)
{
    Options options;
    std::vector<int32_t> modifiers;
    int32_t clicks = 0;
    std::string error;
    const NumberRule clicksRule {
        .optionName = "--clicks",
        .isRequired = true,
        .minValue = -MAX_SCROLL_CLICKS,
        .maxValue = MAX_SCROLL_CLICKS,
    };
    if (!ParseMouseOptions(ALLOWED_OPTIONS, args, options, modifiers, error) ||
        !ParseNumber(options, clicksRule, clicks, error) ||
        !ValidateScrollClicks(clicks, error)) {
        return ParameterError(error.empty() ? "options must use documented --name value once" : error,
            "Please provide clicks in [-100,-1] or [1,100]");
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
    const int32_t value = clicks > 0 ? SCROLL_ANGLE_PER_CLICK : -SCROLL_ANGLE_PER_CLICK;
    const int32_t count = clicks > 0 ? clicks : -clicks;
    const int32_t axis = PointerEvent::AXIS_TYPE_SCROLL_VERTICAL;
    ret = session.mouse->BeginAxis(axis, value);
    if (ret != 0) {
        return HandleControllerError(ret, "BeginAxis");
    }
    for (int32_t index = 1; index < count; ++index) {
        ret = session.mouse->UpdateAxis(axis, value);
        if (ret != 0) {
            return HandleControllerError(ret, "UpdateAxis");
        }
    }
    ret = session.mouse->EndAxis(axis);
    if (ret != 0) {
        return HandleControllerError(ret, "EndAxis");
    }
    ret = ReleaseModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseKey");
    }
    return OutputPrinter::PrintSuccess({ { "action", "mouse-scroll" }, { "clicks", clicks } });
}
} // namespace OHOS::MMI::InputCli
