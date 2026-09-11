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

#include "mouse_support.h"

#include <chrono>
#include <cstdint>
#include <thread>

#include "input_manager.h"
#include "modifier.h"
#include "pointer_event.h"
#include "printer.h"

namespace OHOS::MMI::InputCli {
namespace {
constexpr int32_t MAX_DRAG_DURATION_MS = 10000;
constexpr int32_t DEFAULT_HOLD_DURATION_MS = 100;
constexpr int32_t MIN_HOLD_DURATION_MS = 50;
constexpr int32_t MAX_HOLD_DURATION_MS = 200;
} // namespace

bool ParseMouseOptions(const std::set<std::string> &allowed, const std::vector<std::string> &args,
    Options &options, std::vector<int32_t> &modifiers, std::string &error)
{
    if (!ParseOptionPairs(args, allowed, options, error)) {
        return false;
    }
    const auto modifier = options.find("--modifier");
    return modifier == options.end() || ParseModifiers(modifier->second, modifiers, error);
}

bool ParseButton(const Options &options, int32_t &button, std::string &error)
{
    const auto option = options.find("--button");
    const std::string value = option == options.end() ? "left" : option->second;
    if (value == "left") {
        button = PointerEvent::MOUSE_BUTTON_LEFT;
    } else if (value == "right") {
        button = PointerEvent::MOUSE_BUTTON_RIGHT;
    } else if (value == "middle") {
        button = PointerEvent::MOUSE_BUTTON_MIDDLE;
    } else {
        error = "button must be left, right, or middle";
        return false;
    }
    return true;
}

bool ParsePoint(const Options &options, bool needsButton, PointOptions &result, std::string &error)
{
    const NumberRule xRule = CoordinateRule("--x");
    const NumberRule yRule = CoordinateRule("--y");
    const NumberRule displayIdRule = DisplayIdRule("--displayId");
    const NumberRule holdDurationRule {
        .optionName = "--holdDuration",
        .isRequired = false,
        .defaultValue = DEFAULT_HOLD_DURATION_MS,
        .minValue = MIN_HOLD_DURATION_MS,
        .maxValue = MAX_HOLD_DURATION_MS,
    };
    return ParseNumber(options, xRule, result.x, error) &&
        ParseNumber(options, yRule, result.y, error) &&
        ParseNumber(options, displayIdRule, result.displayId, error) &&
        (!needsButton || (ParseNumber(options, holdDurationRule, result.holdDuration, error) &&
            ParseButton(options, result.button, error)));
}

bool ParseDrag(const Options &options, DragOptions &result, std::string &error)
{
    const NumberRule srcXRule = CoordinateRule("--srcX");
    const NumberRule srcYRule = CoordinateRule("--srcY");
    const NumberRule dstXRule = CoordinateRule("--dstX");
    const NumberRule dstYRule = CoordinateRule("--dstY");
    const NumberRule srcDisplayIdRule = DisplayIdRule("--srcDisplayId");
    const NumberRule dstDisplayIdRule = DisplayIdRule("--dstDisplayId");
    const NumberRule durationRule {
        .optionName = "--duration",
        .isRequired = false,
        .defaultValue = 0,
        .minValue = 0,
        .maxValue = MAX_DRAG_DURATION_MS,
    };
    return ParseNumber(options, srcXRule, result.srcX, error) &&
        ParseNumber(options, srcYRule, result.srcY, error) &&
        ParseNumber(options, dstXRule, result.dstX, error) &&
        ParseNumber(options, dstYRule, result.dstY, error) &&
        ParseNumber(options, srcDisplayIdRule, result.srcDisplayId, error) &&
        ParseNumber(options, dstDisplayIdRule, result.dstDisplayId, error) &&
        ParseNumber(options, durationRule, result.duration, error) &&
        ParseButton(options, result.button, error);
}

bool ValidateScrollClicks(int32_t clicks, std::string &error)
{
    if (clicks == 0 || clicks < -MAX_SCROLL_CLICKS || clicks > MAX_SCROLL_CLICKS) {
        error = "clicks must be in [-100, -1] or [1, 100]";
        return false;
    }
    return true;
}

int32_t CreateControllers(const std::vector<int32_t> &modifiers, MouseSession &session)
{
    int32_t ret = InputManager::GetInstance()->CreateMouseController(session.mouse);
    if (ret != 0 || session.mouse == nullptr) {
        return HandleControllerError(ret, "CreateMouseController");
    }
    if (modifiers.empty()) {
        return 0;
    }
    ret = InputManager::GetInstance()->CreateKeyboardController(session.keyboard);
    if (ret != 0 || session.keyboard == nullptr) {
        return HandleControllerError(ret, "CreateKeyboardController");
    }
    return 0;
}

int32_t MoveTo(const MouseSession &session, int32_t displayId, int32_t x, int32_t y)
{
    const int32_t ret = session.mouse->MoveTo(displayId, x, y);
    return ret == 0 ? 0 : HandleControllerError(ret, "MoveTo");
}

int32_t ClickButton(const MouseSession &session, const PointOptions &options)
{
    int32_t ret = session.mouse->PressButton(options.button);
    if (ret != 0) {
        return HandleControllerError(ret, "PressButton");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(options.holdDuration));
    ret = session.mouse->ReleaseButton(options.button);
    return ret == 0 ? 0 : HandleControllerError(ret, "ReleaseButton");
}
} // namespace OHOS::MMI::InputCli
