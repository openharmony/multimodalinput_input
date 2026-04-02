/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef JS_MOUSE_CONTROLLER_H
#define JS_MOUSE_CONTROLLER_H

#include <map>
#include <memory>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Mouse controller for simulating mouse operations
 *
 * This class maintains client-side state for mouse button presses,
 * axis events, and cursor position. Each instance is independent.
 */
class JsMouseController {
public:
    JsMouseController();
    ~JsMouseController();

    /**
     * @brief Move mouse cursor to specified position
     * @param displayId Display ID
     * @param x X coordinate (will be clamped to >= 0)
     * @param y Y coordinate (will be clamped to >= 0)
     * @return RET_OK on success, error code otherwise
     */
    int32_t MoveTo(int32_t displayId, int32_t x, int32_t y);

    /**
     * @brief Press mouse button
     * @param button Button ID
     * @return RET_OK on success, error code otherwise
     */
    int32_t PressButton(int32_t button);

    /**
     * @brief Release mouse button
     * @param button Button ID
     * @return RET_OK on success, error code otherwise
     */
    int32_t ReleaseButton(int32_t button);

    /**
     * @brief Begin axis event (e.g., scroll wheel)
     * @param axis Axis type
     * @param value Axis value
     * @return RET_OK on success, error code otherwise
     */
    int32_t BeginAxis(int32_t axis, int32_t value);

    /**
     * @brief Update ongoing axis event
     * @param axis Axis type
     * @param value Axis value
     * @return RET_OK on success, error code otherwise
     */
    int32_t UpdateAxis(int32_t axis, int32_t value);

    /**
     * @brief End axis event
     * @param axis Axis type
     * @return RET_OK on success, error code otherwise
     */
    int32_t EndAxis(int32_t axis);

private:
    /**
     * @brief Create a PointerEvent with specified action
     * @param action Pointer action type
     * @return Shared pointer to PointerEvent
     */
    std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action);

    /**
     * @brief Inject pointer event to system
     * @param event Pointer event to inject
     * @return RET_OK on success, error code otherwise
     */
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> event);

    /**
     * @brief Validate and clamp coordinates
     * @param x X coordinate (will be modified)
     * @param y Y coordinate (will be modified)
     * @param displayId Display ID
     * @return true if valid, false otherwise
     */
    bool ValidateCoordinates(int32_t& x, int32_t& y, int32_t displayId);

    /**
     * @brief Create a PointerItem with current cursor position
     * @return PointerItem with cursor position set
     */
    PointerEvent::PointerItem CreatePointerItem();

    // Button states: button ID -> pressed state
    std::map<int32_t, bool> buttonStates_;

    // Record the down time for each pressed button
    std::map<int32_t, int64_t> buttonDownTimes_;

    // Axis event state
    struct AxisState {
        bool inProgress = false;
        int32_t axisType = -1;
        int32_t lastValue = 0;
    } axisState_;

    // Current cursor position
    struct CursorPosition {
        int32_t displayId = 0;
        int32_t x = 0;
        int32_t y = 0;
    } cursorPos_;

    // Mutex to protect state (for thread safety)
    mutable std::mutex mutex_;
};

} // namespace MMI
} // namespace OHOS

#endif // JS_MOUSE_CONTROLLER_H
