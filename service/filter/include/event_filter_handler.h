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

#ifndef EVENT_FILTER_HANDLER_H
#define EVENT_FILTER_HANDLER_H

#include "event_filter_death_recipient.h"
#include "i_event_filter.h"
#include "i_input_event_handler.h"

namespace OHOS {
namespace MMI {
class EventFilterHandler final : public IInputEventHandler, public std::enable_shared_from_this<EventFilterHandler> {
public:
    EventFilterHandler() = default;
    DISALLOW_COPY_AND_MOVE(EventFilterHandler);
    ~EventFilterHandler() override = default;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority, uint32_t deviceTags,
        int32_t clientPid);
    int32_t RemoveInputEventFilter(int32_t filterId, int32_t clientPid);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    bool HandleKeyEventFilter(std::shared_ptr<KeyEvent> event);
    bool HandlePointerEventFilter(std::shared_ptr<PointerEvent> event);
private:
    bool TouchPadKnuckleDoubleClickHandle(std::shared_ptr<KeyEvent> event);
private:
    std::mutex lockFilter_;
    struct FilterInfo {
        const sptr<IEventFilter> filter;
        sptr<IRemoteObject::DeathRecipient> deathRecipient { nullptr };
        const int32_t filterId;
        const int32_t priority;
        const uint32_t deviceTags;
        const int32_t clientPid;
        bool IsSameClient(int32_t id, int32_t pid) const { return ((filterId == id) && (clientPid == pid)); }
    };
    std::list<FilterInfo> filters_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_FILTER_HANDLER_H