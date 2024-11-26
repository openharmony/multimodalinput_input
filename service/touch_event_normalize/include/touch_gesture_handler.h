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

#ifndef TOUCH_GESTURE_HANDLER_H
#define TOUCH_GESTURE_HANDLER_H

#include <memory>

#include <cJSON.h>
#include <nocopyable.h>

#include "delegate_interface.h"
#include "key_command_handler.h"
#include "touch_gesture_manager.h"

namespace OHOS {
namespace MMI {
class TouchGestureHandler final {
    struct Handler {
        std::set<GestureMode> modes_;
        int32_t nFingers_ {};
        Ability ability_ {};
    };

public:
    TouchGestureHandler(std::shared_ptr<DelegateInterface> delegate,
                        std::shared_ptr<TouchGestureManager> touchGestureMgr);
    ~TouchGestureHandler();
    DISALLOW_COPY_AND_MOVE(TouchGestureHandler);

private:
    void LoadGestureHandlerConfig();
    void ReadGestureHandlerConfig(const std::string &cfgPath);
    void ReadGestureHandlerConfig(cJSON *jsonHandler);
    std::set<GestureMode> ConvertGestureModes(const std::string &sGestureModes) const;
    GestureMode ConvertGestureMode(const std::string &sGestureMode) const;
    void RegisterGestureHandler(const Handler &handler) const;
    TouchGestureType GestureMode2GestureType(GestureMode gestureMode) const;
    void UnregisterGestureHandlers();
    void UnregisterGestureHandler(const Handler &handler);
    void StartMonitor();
    void StopMonitor();
    void ProcessGestureEvent(std::shared_ptr<PointerEvent> event);
    GestureMode GetGestureMode(std::shared_ptr<PointerEvent> event) const;
    void LaunchAbility(const Ability &ability);

    std::weak_ptr<DelegateInterface> delegate_;
    std::weak_ptr<TouchGestureManager> touchGestureMgr_;
    std::vector<Handler> handlers_;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_GESTURE_HANDLER_H