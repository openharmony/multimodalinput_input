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

#ifndef KEYBOARD_CONTROLLER_IMPL_H
#define KEYBOARD_CONTROLLER_IMPL_H

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "key_event.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Keyboard controller implementation (core logic)
 * @note Thread-safe, can be used by multiple API layers (NAPI, ANI, NDK)
 */
class KeyboardControllerImpl {
public:
    KeyboardControllerImpl();
    ~KeyboardControllerImpl();

    /**
     * @brief Press key down
     * @param keyCode Key code
     * @return RET_OK on success, error code otherwise
     */
    int32_t PressKey(int32_t keyCode);

    /**
     * @brief Release key up
     * @param keyCode Key code
     * @return RET_OK on success, error code otherwise
     */
    int32_t ReleaseKey(int32_t keyCode);

private:
    /**
     * @brief Create key event with specified action and key code
     * @param action Key action (KEY_ACTION_DOWN / KEY_ACTION_UP)
     * @param keyCode Key code
     * @return Shared pointer to KeyEvent, nullptr on failure
     */
    std::shared_ptr<KeyEvent> CreateKeyEvent(int32_t action, int32_t keyCode);

    /**
     * @brief Inject key event to input system
     * @param event Key event to inject
     * @return RET_OK on success, error code otherwise
     */
    int32_t InjectKeyEvent(std::shared_ptr<KeyEvent> event);

    // State management
    std::vector<int32_t> pressedKeys_;           // Currently pressed keys (in order)
    std::map<int32_t, int64_t> keyDownTimes_;    // Key down timestamps

    mutable std::mutex mutex_;  // Thread safety

    static constexpr size_t MAX_PRESSED_KEYS = 10;  // Maximum simultaneous pressed keys
};

} // namespace MMI
} // namespace OHOS

#endif // KEYBOARD_CONTROLLER_IMPL_H
