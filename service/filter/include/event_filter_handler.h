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

#ifndef EVENT_FILTER_HANDLER_H
#define EVENT_FILTER_HANDLER_H

#include <mutex>
#include "nocopyable.h"

#include "i_event_filter.h"
#include "i_input_event_handler.h"

namespace OHOS {
namespace MMI {
class EventFilterHandler : public IInputEventHandler {
public:
    EventFilterHandler();
    DISALLOW_COPY_AND_MOVE(EventFilterHandler);
    ~EventFilterHandler();
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t AddInputEventFilter(sptr<IEventFilter> filter);
    bool HandlePointerEventFilter(std::shared_ptr<PointerEvent> point);
private:
    std::mutex lockFilter_;
    sptr<IEventFilter> filter_ {nullptr};
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_FILTER_HANDLER_H