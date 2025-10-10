/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MMI_KEY_COMMAND_HANDLER_MOCK_H
#define MMI_KEY_COMMAND_HANDLER_MOCK_H

#include <gmock/gmock.h>
#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
struct ShortcutKey {
    int32_t finalKey { -1 };
};

class IKeyCommandHandler {
public:
    IKeyCommandHandler() = default;
    virtual ~IKeyCommandHandler() = default;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    virtual void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) = 0;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    virtual void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    virtual void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) = 0;
#endif // OHOS_BUILD_ENABLE_TOUCH
    virtual bool SkipKnuckleDetect() = 0;
};

class KeyCommandHandler : public IKeyCommandHandler {
public:
    KeyCommandHandler() = default;
    virtual ~KeyCommandHandler() override = default;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    MOCK_METHOD(void, HandleKeyEvent, (const std::shared_ptr<KeyEvent>));
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    MOCK_METHOD(void, HandlePointerEvent, (const std::shared_ptr<PointerEvent>));
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    MOCK_METHOD(void, HandleTouchEvent, (const std::shared_ptr<PointerEvent>));
#endif // OHOS_BUILD_ENABLE_TOUCH
    MOCK_METHOD(bool, SkipKnuckleDetect, ());
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_COMMAND_HANDLER_MOCK_H