/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MOUSE_EVENT_HANDLER_H
#define MOUSE_EVENT_HANDLER_H

#include <memory>
#include "libinput.h"
#include "pointer_event.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class MouseEventHandler : public DelayedSingleton<MouseEventHandler>,
    public std::enable_shared_from_this<MouseEventHandler> {
public:
    MouseEventHandler();
    ~MouseEventHandler() = default;

    std::shared_ptr<PointerEvent> GetPointerEvent();
    void Normalize(libinput_event *event);
private:
    void HandleMotionInner(libinput_event_pointer* data);
    void HandleButonInner(libinput_event_pointer* data, PointerEvent::PointerItem& pointerItem);
    void HandleAxisInner(libinput_event_pointer* data);
    void HandlePostInner(libinput_event_pointer* data, int32_t deviceId, PointerEvent::PointerItem& pointerItem);
    void DumpInner();
private:
    std::shared_ptr<PointerEvent> pointerEvent_;
    int32_t timerId_ = -1;
    double absolutionX_ = 0;
    double absolutionY_ = 0;
    int32_t buttionId_ = -1;
};
} // namespace MMI
} // namespace OHOS
#define MouseEventHdr OHOS::MMI::MouseEventHandler::GetInstance()

#endif // MOUSE_EVENT_HANDLER_H