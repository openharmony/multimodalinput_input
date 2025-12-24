/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef I_DELEGATE_INTERFACE_H
#define I_DELEGATE_INTERFACE_H

#include <cstdint>
#include <functional>

#include "input_handler_type.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
using DTaskCallback = std::function<int32_t()>;

class IDelegateInterface {
public:
    using TaskCallback = std::function<int32_t(std::shared_ptr<PointerEvent>)>;

    enum class HandlerMode {
        SYNC,
        ASYNC
    };

    struct HandlerSummary {
        std::string handlerName;
        HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
        HandlerMode mode { HandlerMode::SYNC };
        int32_t priority {};
        uint32_t deviceTags {};
        TouchGestureType gestureType { TOUCH_GESTURE_TYPE_NONE };
        int32_t fingers {};
        TaskCallback cb;
    };

    IDelegateInterface() = default;
    virtual ~IDelegateInterface() = default;

    virtual int32_t OnPostSyncTask(DTaskCallback cb) const = 0;
    virtual int32_t OnPostAsyncTask(DTaskCallback cb) const = 0;

    virtual int32_t AddHandler(InputHandlerType handlerType, const HandlerSummary &summary) = 0;
    virtual void RemoveHandler(InputHandlerType handlerType, const std::string &name) = 0;
    virtual bool HasHandler(const std::string &name) const = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_DELEGATE_INTERFACE_H