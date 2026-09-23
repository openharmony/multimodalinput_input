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

#include "mouse_drag_command.h"

#include <chrono>
#include <cstdint>
#include <set>
#include <thread>

#include "input_manager.h"
#include "modifier.h"
#include "mouse_support.h"
#include "printer.h"

namespace OHOS::MMI::InputCli {
namespace {
constexpr int32_t DRAG_FRAME_INTERVAL_MS = 16;

const std::set<std::string> ALLOWED_OPTIONS = {
    "--srcDisplayId",
    "--srcX",
    "--srcY",
    "--dstDisplayId",
    "--dstX",
    "--dstY",
    "--button",
    "--duration",
    "--modifier",
};

int32_t RunDragSteps(const MouseSession &session, const DragOptions &options)
{
    if (options.duration == 0) {
        return MoveTo(session, options.dstDisplayId, options.dstX, options.dstY);
    }
    DragPath path { options.srcDisplayId, options.srcX, options.srcY, options.dstDisplayId, options.dstX,
        options.dstY };
    const bool crossDisplay = options.srcDisplayId != options.dstDisplayId;
    if (crossDisplay) {
        int32_t sourceX = 0;
        int32_t sourceY = 0;
        int32_t targetX = 0;
        int32_t targetY = 0;
        int32_t ret = InputManager::GetInstance()->GetGlobalCoordinates(path.srcDisplayId, path.srcX, path.srcY,
            sourceX, sourceY);
        if (ret != 0) {
            return HandleControllerError(ret, "GetGlobalCoordinates");
        }
        ret = InputManager::GetInstance()->GetGlobalCoordinates(path.dstDisplayId, path.dstX, path.dstY, targetX,
            targetY);
        if (ret != 0) {
            return HandleControllerError(ret, "GetGlobalCoordinates");
        }
        path.srcX = sourceX;
        path.srcY = sourceY;
        path.dstX = targetX;
        path.dstY = targetY;
    }
    const auto steps = BuildDragSteps(options.duration, path);
    for (const auto &step : steps) {
        std::this_thread::sleep_for(std::chrono::milliseconds(step.delayMs));
        if (!step.move) {
            continue;
        }
        const int32_t ret = crossDisplay ? session.mouse->MoveToGlobal(step.x, step.y)
                                         : MoveTo(session, path.dstDisplayId, step.x, step.y);
        if (ret != 0) {
            return HandleControllerError(ret, crossDisplay ? "MoveToGlobal" : "MoveTo");
        }
    }
    return 0;
}
} // namespace

std::string MouseDragCommand::GetName() const
{
    return "mouse-drag";
}

std::string MouseDragCommand::GetDescription() const
{
    return "Simulate mouse drag";
}

std::string MouseDragCommand::GetTitle() const
{
    return "Simulate mouse drag from source to destination";
}

std::string MouseDragCommand::GetUsage() const
{
    return "ohos-input mouse-drag [options]";
}

std::vector<ParameterDoc> MouseDragCommand::GetParameters() const
{
    return {
        { "--srcDisplayId <number>", "Source display ID (optional, range: >=0, default: 0)" },
        { "--srcX <integer>", "Source X coordinate (required, range: >=0)" },
        { "--srcY <integer>", "Source Y coordinate (required, range: >=0)" },
        { "--dstDisplayId <number>", "Destination display ID (optional, range: >=0, default: 0)" },
        { "--dstX <integer>", "Destination X coordinate (required, range: >=0)" },
        { "--dstY <integer>", "Destination Y coordinate (required, range: >=0)" },
        { "--button <key>",
            "Mouse button to hold during drag (optional, values: [left, right, middle], default: left)" },
        { "--duration <number>",
            "Total drag duration in ms (optional, range: [0, 10000], 0 means instant, default: 0)" },
        { "--modifier <keys>",
            "Modifier keys (optional, values: [ctrl, alt, shift, meta], pipe-separated with |, in press order, "
            "no duplicates)" },
    };
}

std::vector<std::string> MouseDragCommand::GetExamples() const
{
    return {
        "# Left-button drag from (100,100) to (300,300) over 500ms",
        "ohos-input mouse-drag --srcX 100 --srcY 100 --dstX 300 --dstY 300 --duration 500",
        "",
        "# Instant drag (no intermediate move steps)",
        "ohos-input mouse-drag --srcX 100 --srcY 100 --dstX 300 --dstY 300 --duration 0",
        "",
        "# Cross-display drag",
        "ohos-input mouse-drag --srcDisplayId 0 --srcX 100 --srcY 100 --dstDisplayId 1 --dstX 200 --dstY 200"
        " --duration 500",
    };
}

int32_t MouseDragCommand::Execute(const std::vector<std::string> &args)
{
    Options options;
    std::vector<int32_t> modifiers;
    DragOptions drag;
    std::string error;
    if (!ParseMouseOptions(ALLOWED_OPTIONS, args, options, modifiers, error) ||
        !ParseDrag(options, drag, error)) {
        return ParameterError(error.empty() ? "options must use documented --name value once" : error,
            "Please use documented mouse drag arguments");
    }
    MouseSession session;
    int32_t ret = CreateControllers(modifiers, session);
    if (ret != 0) {
        return ret;
    }
    ret = MoveTo(session, drag.srcDisplayId, drag.srcX, drag.srcY);
    if (ret != 0) {
        return ret;
    }
    ret = PressModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "PressKey");
    }
    ret = session.mouse->PressButton(drag.button);
    if (ret != 0) {
        return HandleControllerError(ret, "PressButton");
    }
    ret = RunDragSteps(session, drag);
    if (ret != 0) {
        session.mouse->ReleaseButton(drag.button);
        return ret;
    }
    ret = session.mouse->ReleaseButton(drag.button);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseButton");
    }
    ret = ReleaseModifiers(session.keyboard, modifiers);
    if (ret != 0) {
        return HandleControllerError(ret, "ReleaseKey");
    }
    return OutputPrinter::PrintSuccess({ { "action", "mouse-drag" }, { "srcDisplayId", drag.srcDisplayId },
        { "srcX", drag.srcX }, { "srcY", drag.srcY }, { "dstDisplayId", drag.dstDisplayId },
        { "dstX", drag.dstX }, { "dstY", drag.dstY } });
}

std::vector<DragStep> BuildDragSteps(int32_t duration, const DragPath &path)
{
    std::vector<DragStep> steps;
    if (duration <= 0) {
        return steps;
    }
    const bool shouldMove =
        path.srcDisplayId != path.dstDisplayId || path.srcX != path.dstX || path.srcY != path.dstY;
    const int32_t count = (duration + DRAG_FRAME_INTERVAL_MS - 1) / DRAG_FRAME_INTERVAL_MS;
    const int64_t deltaX = static_cast<int64_t>(path.dstX) - path.srcX;
    const int64_t deltaY = static_cast<int64_t>(path.dstY) - path.srcY;
    for (int32_t index = 1; index <= count; ++index) {
        const int32_t delay =
            index == count ? duration - DRAG_FRAME_INTERVAL_MS * (count - 1) : DRAG_FRAME_INTERVAL_MS;
        steps.push_back({ static_cast<int32_t>(path.srcX + deltaX * index / count),
            static_cast<int32_t>(path.srcY + deltaY * index / count), delay, shouldMove });
    }
    return steps;
}
} // namespace OHOS::MMI::InputCli
