/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef TOUCH_TRANSFORM_PROCESSOR_H
#define TOUCH_TRANSFORM_PROCESSOR_H
#include "nocopyable.h"
#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class TouchTransformProcessor : public TransformProcessor {
public:
    explicit TouchTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(TouchTransformProcessor);
    virtual ~TouchTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;

private:
    bool OnEventTouchDown(struct libinput_event *event);
    bool OnEventTouchMotion(struct libinput_event *event);
    bool OnEventTouchUp(struct libinput_event *event);
    int32_t GetTouchToolType(struct libinput_event_touch *data, struct libinput_device *device);
    int32_t GetTouchToolType(struct libinput_device *device);
    void InitToolTypes();
private:
    const int32_t deviceId_ { -1 };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::vector<std::pair<int32_t, int32_t>> vecToolType_;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_TRANSFORM_PROCESSOR_H