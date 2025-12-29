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

#ifndef TOUCH_GESTURE_MANAGER_H
#define TOUCH_GESTURE_MANAGER_H

#include <memory>

#include <nocopyable.h>

#include "i_input_service_context.h"
#include "i_touch_gesture_manager.h"
#include "touch_gesture_adapter.h"

namespace OHOS {
namespace MMI {
class TouchGestureManager final : public ITouchGestureManager {
public:
    TouchGestureManager(IInputServiceContext *env);
    ~TouchGestureManager();
    DISALLOW_COPY_AND_MOVE(TouchGestureManager);

    bool DoesSupportGesture(TouchGestureType gestureType, int32_t nFingers) const override;
    bool AddHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers) override;
    void RemoveHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers) override;
    bool HasHandler() const override;
    void HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent) override;
    void Dump(int32_t fd, const std::vector<std::string> &args) override;
    void OnSessionLost(int32_t session) override;

private:
    void StartRecognization(TouchGestureType gestureType, int32_t nFingers);
    void StopRecognization(TouchGestureType gestureType, int32_t nFingers);
    void RemoveAllHandlers();

    IInputServiceContext *env_ { nullptr };
    std::shared_ptr<TouchGestureAdapter> touchGesture_;
    std::set<Handler> handlers_;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_GESTURE_MANAGER_H