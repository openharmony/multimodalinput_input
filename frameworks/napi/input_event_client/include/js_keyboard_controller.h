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

#ifndef JS_KEYBOARD_CONTROLLER_H
#define JS_KEYBOARD_CONTROLLER_H

#include <memory>

#include "keyboard_controller_impl.h"

namespace OHOS {
namespace MMI {

/**
 * @brief NAPI wrapper for KeyboardControllerImpl
 *
 * This class is a thin adapter layer that converts JS parameters to C++ calls.
 * All core logic is delegated to KeyboardControllerImpl.
 */
class JsKeyboardController {
public:
    JsKeyboardController();
    ~JsKeyboardController() = default;

    /**
     * @brief Press a key
     * @param keyCode Key code
     * @return RET_OK on success, error code otherwise
     */
    int32_t PressKey(int32_t keyCode);

    /**
     * @brief Release a key
     * @param keyCode Key code
     * @return RET_OK on success, error code otherwise
     */
    int32_t ReleaseKey(int32_t keyCode);

private:
    // Core implementation instance
    std::shared_ptr<KeyboardControllerImpl> impl_;
};

} // namespace MMI
} // namespace OHOS

#endif // JS_KEYBOARD_CONTROLLER_H
