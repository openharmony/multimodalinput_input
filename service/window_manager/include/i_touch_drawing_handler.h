/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef I_TOUCH_DRAWING_HANDLER_H
#define I_TOUCH_DRAWING_HANDLER_H

#include "old_display_info.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class ITouchDrawingHandler {
public:
    ITouchDrawingHandler() = default;
    virtual ~ITouchDrawingHandler() = default;

    virtual void UpdateDisplayInfo(const OLD::DisplayInfo &displayInfo) = 0;
    virtual void TouchDrawHandler(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual void RotationScreen() = 0;
    virtual void UpdateLabels(bool isOn) = 0;
    virtual bool IsValidScaleInfo() = 0;
    virtual void UpdateBubbleData(bool isOn) = 0;
    virtual void SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId) = 0;
    virtual void Dump(int32_t fd, const std::vector<std::string> &args) = 0;
    virtual bool IsWindowRotation() const = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_TOUCH_DRAWING_HANDLER_H
