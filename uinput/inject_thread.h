/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INJECT_THREAD_H
#define INJECT_THREAD_H

#include <mutex>

#include "virtual_keyboard.h"
#include "virtual_touch_screen.h"

namespace OHOS {
namespace MMI {
extern std::unique_ptr<VirtualTouchScreen> g_pTouchScreen;
extern std::unique_ptr<VirtualKeyboard> g_pKeyboard;

struct InjectInputEvent {
    int32_t deviceId { 0 };
    int32_t type { 0 };
    int32_t code { 0 };
    int32_t value { 0 };
};

class InjectThread {
public:
    static constexpr int32_t TOUCH_SCREEN_DEVICE_ID = 1;
    static constexpr int32_t KEYBOARD_DEVICE_ID = 2;
    InjectThread() = default;
    virtual ~InjectThread() = default;
    void InjectFunc() const;
    void WaitFunc(InjectInputEvent injectInputEvent) const;

private:
    static std::mutex mutex_;
    static std::condition_variable conditionVariable_;
    static std::vector<InjectInputEvent> injectQueue_;
};
} // namespace MMI
} // namespace OHOS
#endif // INJECT_THREAD_H