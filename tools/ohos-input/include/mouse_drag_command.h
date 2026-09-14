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

#ifndef OHOS_INPUT_MOUSE_DRAG_COMMAND_H
#define OHOS_INPUT_MOUSE_DRAG_COMMAND_H

#include <cstdint>
#include <string>
#include <vector>

#include "command.h"

namespace OHOS::MMI::InputCli {
struct DragPath {
    int32_t srcDisplayId;
    int32_t srcX;
    int32_t srcY;
    int32_t dstDisplayId;
    int32_t dstX;
    int32_t dstY;
};

struct DragStep {
    int32_t x { 0 };
    int32_t y { 0 };
    int32_t delayMs { 0 };
    bool move { false };
};

std::vector<DragStep> BuildDragSteps(int32_t duration, const DragPath &path);

class MouseDragCommand final : public Command {
public:
    std::string GetName() const override;
    std::string GetDescription() const override;
    std::string GetTitle() const override;
    std::string GetUsage() const override;
    std::vector<ParameterDoc> GetParameters() const override;
    std::vector<std::string> GetExamples() const override;
    int32_t Execute(const std::vector<std::string> &args) override;
};
} // namespace OHOS::MMI::InputCli

#endif
