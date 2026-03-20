/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef POINTER_DISPATCH_EVENT_CACHE_H
#define POINTER_DISPATCH_EVENT_CACHE_H

#include <memory>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class PointerDispatchEventCache final {
public:
    void Update(const std::shared_ptr<PointerEvent>& pointerEvent);
    std::shared_ptr<PointerEvent> GetForDispatch(int32_t pointerAction) const;
    std::shared_ptr<PointerEvent> GetTouchEvent() const;
    void ClearDeviceEvents(int32_t deviceId);
    void ClearTouch();
    void Reset();

private:
    bool IsStylusEvent(const std::shared_ptr<PointerEvent>& pointerEvent) const;

private:
    std::shared_ptr<PointerEvent> lastTouchEvent_ { nullptr };
    std::shared_ptr<PointerEvent> lastStylusEvent_ { nullptr };
};
} // namespace MMI
} // namespace OHOS

#endif // POINTER_DISPATCH_EVENT_CACHE_H
