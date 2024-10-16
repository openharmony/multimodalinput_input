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

#ifndef GESTURE_MONITOR_HANDLER_H
#define GESTURE_MONITOR_HANDLER_H

#include <map>
#include <set>
#include <nocopyable.h>
#include "input_handler_type.h"

namespace OHOS {
namespace MMI {
struct GestureMonitorHandler {
    GestureMonitorHandler() = default;
    GestureMonitorHandler(const GestureMonitorHandler &other);
    ~GestureMonitorHandler() = default;
    DISALLOW_MOVE(GestureMonitorHandler);
    GestureMonitorHandler& operator=(const GestureMonitorHandler &other);

    static bool CheckMonitorValid(TouchGestureType type, int32_t fingers);
    static bool IsTouchGestureEvent(int32_t pointerAction);

    bool IsMatchGesture(int32_t action, int32_t count) const;
    void AddGestureMonitor(TouchGestureType type, int32_t fingers);
    bool RemoveGestureMonitor(TouchGestureType type, int32_t fingers);

    int32_t fingers_ { 0 };
    TouchGestureType gestureType_ { TOUCH_GESTURE_TYPE_NONE };
    std::multimap<TouchGestureType, std::set<int32_t>> touchGestureInfo_;
};
} // namespace MMI
} // namespace OHOS
#endif // GESTURE_MONITOR_HANDLER_H