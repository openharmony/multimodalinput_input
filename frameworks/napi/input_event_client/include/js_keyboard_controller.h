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

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "key_event.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Keyboard controller for simulating keyboard operations
 *
 * This class maintains client-side state for key presses.
 * Supports recording and playback scenarios where keys can be pressed repeatedly.
 */
class JsKeyboardController {
public:
    JsKeyboardController();
    ~JsKeyboardController();

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
    /**
     * @brief Create a KeyEvent with specified action
     * @param action Key action type (KEY_ACTION_DOWN / KEY_ACTION_UP)
     * @param keyCode Key code
     * @return Shared pointer to KeyEvent
     */
    std::shared_ptr<KeyEvent> CreateKeyEvent(int32_t action, int32_t keyCode);

    /**
     * @brief Inject key event to system
     * @param event Key event to inject
     * @return RET_OK on success, error code otherwise
     */
    int32_t InjectKeyEvent(std::shared_ptr<KeyEvent> event);

    // Currently pressed keys in order (maximum 5)
    std::vector<int32_t> pressedKeys_;

    // Record the down time for each pressed key
    std::map<int32_t, int64_t> keyDownTimes_;

    // Mutex to protect state (for thread safety)
    mutable std::mutex mutex_;

    // Maximum number of simultaneously pressed keys
    static constexpr size_t MAX_PRESSED_KEYS = 5;
};

} // namespace MMI
} // namespace OHOS

#endif // JS_KEYBOARD_CONTROLLER_H
