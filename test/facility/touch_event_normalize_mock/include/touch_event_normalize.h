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

#ifndef MMI_TOUCH_EVENT_NORMALIZE_MOCK_H
#define MMI_TOUCH_EVENT_NORMALIZE_MOCK_H

#include "gmock/gmock.h"
#include "pointer_event.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class ITouchEventNormalize {
public:
    enum class DeviceType : int32_t {
        KEYBOARD,
        POINTER,
        TOUCH,
        TABLET_TOOL,
        TABLET_PAD,
        GESTURE,
        SWITCH,
        JOYSTICK,
        AISENSOR,
        TOUCH_PAD,
        REMOTE_CONTROL,
        TRACK_BALL,
        KNUCKLE,
        TRACKPAD5,
        GAMEPAD,
    };

    ITouchEventNormalize() = default;
    virtual ~ITouchEventNormalize() = default;

    virtual std::shared_ptr<PointerEvent> GetPointerEvent(int32_t) = 0;
    virtual void GetTouchpadDoubleTapAndDragState(bool&) const = 0;
    virtual int32_t SetTouchpadDoubleTapAndDragState(bool) const = 0;
    virtual int32_t GetTouchpadThreeFingersTapSwitch(bool&) const = 0;
    virtual std::shared_ptr<PointerEvent> OnLibInput(struct libinput_event*, DeviceType) = 0;
};

class TouchEventNormalize final : public ITouchEventNormalize {
public:
    static std::shared_ptr<TouchEventNormalize> GetInstance();
    static void ReleaseInstance();

    TouchEventNormalize() = default;
    ~TouchEventNormalize() override = default;
    DISALLOW_COPY_AND_MOVE(TouchEventNormalize);

    MOCK_METHOD(std::shared_ptr<PointerEvent>, GetPointerEvent, (int32_t));
    MOCK_METHOD(void, GetTouchpadDoubleTapAndDragState, (bool&), (const));
    MOCK_METHOD(int32_t, SetTouchpadDoubleTapAndDragState, (bool), (const));
    MOCK_METHOD(int32_t, GetTouchpadThreeFingersTapSwitch, (bool&), (const));
    MOCK_METHOD(std::shared_ptr<PointerEvent>, OnLibInput, (struct libinput_event*, DeviceType));

private:
    static std::shared_ptr<TouchEventNormalize> instance_;
};

#define TOUCH_EVENT_HDR TouchEventNormalize::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_TOUCH_EVENT_NORMALIZE_MOCK_H
