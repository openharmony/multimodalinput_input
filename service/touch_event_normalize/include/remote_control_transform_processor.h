/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef REMOTE_CONTROL_TRANSFORM_PROCESSOR_H
#define REMOTE_CONTROL_TRANSFORM_PROCESSOR_H

#include "aggregator.h"
#include "timer_manager.h"
#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class Remote_ControlTransformProcessor final : public TransformProcessor {
public:
    explicit Remote_ControlTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(Remote_ControlTransformProcessor);
    ~Remote_ControlTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> GetPointerEvent() override { return nullptr; }
    void OnDeviceRemoved() override;

private:
    bool OnEventTouchMotion(struct libinput_event *event);
    bool DumpInner();
    bool HandlePostInner(struct libinput_event* event);
    void InitToolTypes();
private:
    int32_t buttonId_ { -1 };
    int32_t processedCount_ { 0 };
    const int32_t deviceId_ { -1 };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    bool isPressed_ { false };
    std::vector<std::pair<int32_t, int32_t>> vecToolType_;
    Aggregator aggregator_ {
            [](int32_t intervalMs, int32_t repeatCount, std::function<void()> callback) -> int32_t {
                return TimerMgr->AddTimer(intervalMs, repeatCount, std::move(callback),
                    "RemoteControlTransformProcessor-Aggregator");
            },
            [](int32_t timerId) -> int32_t
            {
                return TimerMgr->ResetTimer(timerId);
            },
            [](int32_t timerId) -> int32_t
            {
                return TimerMgr->RemoveTimer(timerId);
            }
    };
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_TRANSFORM_PROCESSOR_H