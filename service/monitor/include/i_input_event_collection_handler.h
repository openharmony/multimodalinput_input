/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef I_INPUT_EVENT_MONITOR_HANDLER_H
#define I_INPUT_EVENT_MONITOR_HANDLER_H

#include <mutex>

#include "key_event.h"
#include "pointer_event.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class IInputEventCollectionHandler {
public:
    static constexpr int32_t DEFAULT_INTERCEPTOR = 10;
    static constexpr int32_t DEFAULT_MONITOR = 20;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    virtual bool HandleEvent(std::shared_ptr<KeyEvent> keyEvent) = 0;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual bool HandleEvent(std::shared_ptr<PointerEvent> pointerEvent) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
};
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_EVENT_MONITOR_HANDLER_H