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

#include <memory>

#include "mouse_controller_impl.h"

namespace OHOS {
namespace MMI {

/**
 * @brief NAPI wrapper for MouseControllerImpl
 *
 * This class is a thin adapter layer that converts JS parameters to C++ calls.
 * All core logic is delegated to MouseControllerImpl.
 */
class JsMouseController {
public:
    JsMouseController();
    ~JsMouseController() = default;

    /**
     * @brief Move mouse cursor to specified position
     * @param displayId Display ID
     * @param x X coordinate
     * @param y Y coordinate
     * @return RET_OK on success, error code otherwise
     */
    int32_t MoveTo(int32_t displayId, int32_t x, int32_t y);

    /**
     * @brief Press mouse button
     * @param button Button ID (JS enum value)
     * @return RET_OK on success, error code otherwise
     */
    int32_t PressButton(int32_t button);

    /**
     * @brief Release mouse button
     * @param button Button ID (JS enum value)
     * @return RET_OK on success, error code otherwise
     */
    int32_t ReleaseButton(int32_t button);

    /**
     * @brief Begin axis event (e.g., scroll wheel)
     * @param axis Axis type (JS enum value)
     * @param value Axis value
     * @return RET_OK on success, error code otherwise
     */
    int32_t BeginAxis(int32_t axis, int32_t value);

    /**
     * @brief Update ongoing axis event
     * @param axis Axis type (JS enum value)
     * @param value Axis value
     * @return RET_OK on success, error code otherwise
     */
    int32_t UpdateAxis(int32_t axis, int32_t value);

    /**
     * @brief End axis event
     * @param axis Axis type (JS enum value)
     * @return RET_OK on success, error code otherwise
     */
    int32_t EndAxis(int32_t axis);

private:
    /**
     * @brief Convert JS button enum to native button ID
     * @param jsButton JS button enum value
     * @return Native button ID
     */
    int32_t ConvertJsButtonToNative(int32_t jsButton);

    /**
     * @brief Convert JS axis enum to native axis type
     * @param jsAxis JS axis enum value
     * @return Native axis type
     */
    int32_t ConvertJsAxisToNative(int32_t jsAxis);

    // Core implementation instance
    std::shared_ptr<MouseControllerImpl> impl_;
};

} // namespace MMI
} // namespace OHOS

#endif // JS_MOUSE_CONTROLLER_H
