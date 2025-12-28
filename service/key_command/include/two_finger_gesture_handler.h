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

#ifndef TWO_FINGER_GESTURE_HANDLER_H
#define TWO_FINGER_GESTURE_HANDLER_H

#include "i_key_command_service.h"
#include "key_command_context.h"
#include "key_command_types.h"

namespace OHOS {
namespace MMI {
class TwoFingerGestureHandler {
public:
    explicit TwoFingerGestureHandler(KeyCommandContext& context, IKeyCommandService& service)
        : context_(context), service_(service) {}
    ~TwoFingerGestureHandler() = default;

#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandlePointerActionMoveEvent(const std::shared_ptr<PointerEvent> touchEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    void HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    int32_t LaunchAiScreenAbility(int32_t pid);
    void LaunchTwoFingerAbility(const TwoFingerGesture &twoFinger);

private:
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    void StartTwoFingerGesture();
    void StopTwoFingerGesture();
    bool CheckTwoFingerGestureAction() const;
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    int32_t CheckTwoFingerGesture(int32_t pid);

#ifdef OHOS_BUILD_ENABLE_TOUCH
    int32_t ConvertVPToPX(int32_t vp) const;
#endif // OHOS_BUILD_ENABLE_TOUCH

private:
    KeyCommandContext& context_;
    IKeyCommandService& service_;
};
} // namespace MMI
} // namespace OHOS
#endif // TWO_FINGER_GESTURE_HANDLER_H

