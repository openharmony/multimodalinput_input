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

#ifndef TV_TRANSFORM_PROCESSOR_H
#define TV_TRANSFORM_PROCESSOR_H

#include "nocopyable.h"

#include "aggregator.h"
#include "struct_multimodal.h"
#include "timer_manager.h"
#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class TVTransformProcessor final : public TransformProcessor {
public:
    explicit TVTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(TVTransformProcessor);
    ~TVTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> GetPointerEvent() override { return nullptr; }

private:
    bool OnEventTvTouchMotion(struct libinput_event *event);
    bool DumpInner();
    bool HandlePostInner(struct libinput_event* event, PointerEvent::PointerItem &pointerItem);
    void InitToolTypes();
private:
    int32_t buttonId_ { -1 };
    const int32_t deviceId_ { -1 };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    bool isPressed_ { false };
    std::vector<std::pair<int32_t, int32_t>> vecToolType_;
    Aggregator aggregator_ {
            [](int32_t intervalMs, int32_t repeatCount, std::function<void()> callback) -> int32_t {
                return TimerMgr->AddTimer(intervalMs, repeatCount, std::move(callback));
            },
            [](int32_t timerId) -> int32_t
            {
                return TimerMgr->ResetTimer(timerId);
            }
    };
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_TRANSFORM_PROCESSOR_H