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

class KeyboardControllerImpl {
public:
    KeyboardControllerImpl();
    ~KeyboardControllerImpl();

    int32_t PressKey(int32_t keyCode);
    int32_t ReleaseKey(int32_t keyCode);

private:
    std::shared_ptr<KeyEvent> CreateKeyEvent(int32_t action, int32_t keyCode);
    int32_t InjectKeyEvent(std::shared_ptr<KeyEvent> event);

    std::vector<int32_t> pressedKeys_;
    std::map<int32_t, int64_t> keyDownTimes_;

    mutable std::mutex mutex_;

    static constexpr size_t MAX_PRESSED_KEYS = 10;
};

} // namespace MMI
} // namespace OHOS

#endif // KEYBOARD_CONTROLLER_IMPL_H
