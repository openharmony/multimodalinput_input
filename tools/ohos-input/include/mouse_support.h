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

#ifndef OHOS_INPUT_MOUSE_SUPPORT_H
#define OHOS_INPUT_MOUSE_SUPPORT_H

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "keyboard_controller_impl.h"
#include "mouse_controller_impl.h"
#include "option_parser.h"

namespace OHOS::MMI::InputCli {
inline constexpr int32_t MAX_SCROLL_CLICKS = 100;

struct PointOptions {
    int32_t displayId { 0 };
    int32_t x { 0 };
    int32_t y { 0 };
    int32_t button { 0 };
    int32_t holdDuration { 0 };
    int32_t clickInterval { 0 };
};

struct DragOptions {
    int32_t srcDisplayId { 0 };
    int32_t srcX { 0 };
    int32_t srcY { 0 };
    int32_t dstDisplayId { 0 };
    int32_t dstX { 0 };
    int32_t dstY { 0 };
    int32_t button { 0 };
    int32_t duration { 0 };
};

struct MouseSession {
    std::shared_ptr<KeyboardControllerImpl> keyboard;
    std::shared_ptr<MouseControllerImpl> mouse;
};

bool ParseMouseOptions(const std::set<std::string> &allowed, const std::vector<std::string> &args,
    Options &options, std::vector<int32_t> &modifiers, std::string &error);
bool ParseButton(const Options &options, int32_t &button, std::string &error);
bool ParsePoint(const Options &options, bool needsButton, PointOptions &result, std::string &error);
bool ParseDrag(const Options &options, DragOptions &result, std::string &error);
bool ValidateScrollClicks(int32_t clicks, std::string &error);
int32_t CreateControllers(const std::vector<int32_t> &modifiers, MouseSession &session);
int32_t MoveTo(const MouseSession &session, int32_t displayId, int32_t x, int32_t y);
int32_t ClickButton(const MouseSession &session, const PointOptions &options);
} // namespace OHOS::MMI::InputCli

#endif
