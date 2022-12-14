/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOUSE_TRANSFORM_PROCESSOR_H
#define MOUSE_TRANSFORM_PROCESSOR_H

#include <memory>

#include "libinput.h"
#include "singleton.h"
#include "define_multimodal.h"

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
struct AccelerateCurve {
    std::vector<int32_t> speeds;
    std::vector<double> slopes;
    std::vector<double> diffNums;
};
class MouseTransformProcessor final : public std::enable_shared_from_this<MouseTransformProcessor> {
public:
    DISALLOW_COPY_AND_MOVE(MouseTransformProcessor);
    explicit MouseTransformProcessor(int32_t deviceId);
    ~MouseTransformProcessor() = default;
    std::shared_ptr<PointerEvent> GetPointerEvent() const;
    int32_t Normalize(struct libinput_event *event);
    void Dump(int32_t fd, const std::vector<std::string> &args);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    static void SetAbsolutionLocation(double xPercent, double yPercent);
#endif // OHOS_BUILD_ENABLE_COOPERATE
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool NormalizeMoveMouse(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
private:
    int32_t HandleMotionInner(struct libinput_event_pointer* data);
    int32_t HandleButtonInner(struct libinput_event_pointer* data);
    int32_t HandleAxisInner(struct libinput_event_pointer* data);
    void HandlePostInner(struct libinput_event_pointer* data, PointerEvent::PointerItem &pointerItem);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    void HandleMotionMoveMouse(int32_t offsetX, int32_t offsetY);
    void HandlePostMoveMouse(PointerEvent::PointerItem &pointerItem);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t HandleButtonValueInner(struct libinput_event_pointer* data);
    int32_t HandleMotionAccelerate(struct libinput_event_pointer* data);
    void DumpInner();
    void SetDxDyForDInput(PointerEvent::PointerItem& pointerItem, struct libinput_event_pointer* data);
public:
    static void InitAbsolution();
    static void OnDisplayLost(int32_t displayId);
    static int32_t GetDisplayId();
    static int32_t SetPointerSpeed(int32_t speed);
    static int32_t GetPointerSpeed();
    static bool GetSpeedGain(double vin, double &gain);
    static int32_t SetPointerLocation(int32_t x, int32_t y);

private:
    static double absolutionX_;
    static double absolutionY_;
    static int32_t currentDisplayId_;
    static int32_t speed_;
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    int32_t timerId_ { -1 };
    int32_t buttonId_ { -1 };
    bool isPressed_ { false };
    int32_t deviceId_ { -1 };
};
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_TRANSFORM_PROCESSOR_H