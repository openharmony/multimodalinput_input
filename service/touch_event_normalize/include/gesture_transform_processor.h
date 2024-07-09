/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef GESTURE_TRANSFORM_PROCESSOR_H
#define GESTURE_TRANSFORM_PROCESSOR_H

#include "nocopyable.h"

#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class GestureTransformProcessor final : public TransformProcessor {
public:
    explicit GestureTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(GestureTransformProcessor);
    ~GestureTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> GetPointerEvent() override { return nullptr; }

private:
    const int32_t defaultPointerId { 0 };
    void OnEventTouchPadPinchBegin(libinput_event_gesture *data);
    void OnEventTouchPadPinchUpdate(libinput_event_gesture *data);
    void OnEventTouchPadPinchEnd(libinput_event_gesture *data);
private:
    const int32_t deviceId_ { -1 };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // GESTURE_TRANSFORM_PROCESSOR_H