/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef TABLET_TOOL_TRANSFORM_PROCESSOR_H
#define TABLET_TOOL_TRANSFORM_PROCESSOR_H

#include "nocopyable.h"

#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class TabletToolTransformProcessor final : public TransformProcessor {
public:
    explicit TabletToolTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(TabletToolTransformProcessor);
    ~TabletToolTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> GetPointerEvent() override { return nullptr; }

private:
    int32_t GetToolType(struct libinput_event_tablet_tool* tabletEvent);
    bool OnTip(struct libinput_event* event);
    bool OnTipDown(struct libinput_event_tablet_tool* event);
    bool OnTipMotion(struct libinput_event* event);
    bool OnTipUp(struct libinput_event_tablet_tool* event);

private:
    const int32_t deviceId_ { -1 };
    std::shared_ptr<PointerEvent> pointerEvent_  { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // TABLET_TOOL_TRANSFORM_PROCESSOR_H
