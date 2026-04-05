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

#ifndef MOUSE_CONTROLLER_IMPL_H
#define MOUSE_CONTROLLER_IMPL_H

#include <map>
#include <memory>
#include <mutex>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Mouse controller implementation (core logic)
 * @note Thread-safe, can be used by multiple API layers (NAPI, ANI, NDK)
 */
class MouseControllerImpl {
public:
    MouseControllerImpl();
    ~MouseControllerImpl();

    /**
     * @brief Move mouse cursor to specified position
     * @param displayId Display ID
     * @param x X coordinate (will be clamped if negative)
     * @param y Y coordinate (will be clamped if negative)
     * @return RET_OK on success, error code otherwise
     */
    int32_t MoveTo(int32_t displayId, int32_t x, int32_t y);

    /**
     * @brief Press mouse button
     * @param button Button ID (native button constant)
     * @return RET_OK on success, error code otherwise
     */
    int32_t PressButton(int32_t button);

    /**
     * @brief Release mouse button
     * @param button Button ID (native button constant)
     * @return RET_OK on success, error code otherwise
     */
    int32_t ReleaseButton(int32_t button);

    /**
     * @brief Begin axis event
     * @param axis Axis type (native axis constant)
     * @param value Axis value
     * @return RET_OK on success, error code otherwise
     */
    int32_t BeginAxis(int32_t axis, int32_t value);

    /**
     * @brief Update axis event
     * @param axis Axis type (native axis constant)
     * @param value Axis value
     * @return RET_OK on success, error code otherwise
     */
    int32_t UpdateAxis(int32_t axis, int32_t value);

    /**
     * @brief End axis event
     * @param axis Axis type (native axis constant)
     * @return RET_OK on success, error code otherwise
     */
    int32_t EndAxis(int32_t axis);

private:
    /**
     * @brief Create pointer item with current cursor position
     * @return PointerItem
     */
    PointerEvent::PointerItem CreatePointerItem();

    /**
     * @brief Create pointer event with specified action
     * @param action Pointer action
     * @return Shared pointer to PointerEvent, nullptr on failure
     */
    std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action);

    /**
     * @brief Inject pointer event to input system
     * @param event Pointer event to inject
     * @return RET_OK on success, error code otherwise
     */
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> event);

    /**
     * @brief Validate and clamp coordinates
     * @param x X coordinate (will be modified if invalid)
     * @param y Y coordinate (will be modified if invalid)
     * @param displayId Display ID
     * @return true if coordinates are valid (after clamping)
     */
    bool ValidateCoordinates(int32_t& x, int32_t& y, int32_t displayId);

    // State management
    std::map<int32_t, bool> buttonStates_;       // Button press states
    std::map<int32_t, int64_t> buttonDownTimes_; // Button down timestamps

    struct {
        bool inProgress = false;
        int32_t axisType = -1;
        int32_t lastValue = 0;
    } axisState_;  // Axis event state

    struct {
        int32_t displayId = 0;
        int32_t x = 0;
        int32_t y = 0;
    } cursorPos_;  // Current cursor position

    mutable std::mutex mutex_;  // Thread safety
};

} // namespace MMI
} // namespace OHOS

#endif // MOUSE_CONTROLLER_IMPL_H
