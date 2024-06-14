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

#ifndef TOUCH_EVENT_NORMALIZE_H
#define TOUCH_EVENT_NORMALIZE_H

#include <map>
#include <memory>

#include "proto.h"
#include "singleton.h"
#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class TouchEventNormalize final {
    DECLARE_DELAYED_SINGLETON(TouchEventNormalize);

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

public:
    DISALLOW_COPY_AND_MOVE(TouchEventNormalize);
    std::shared_ptr<PointerEvent> OnLibInput(struct libinput_event *event, DeviceType deviceType);
    int32_t SetTouchpadPinchSwitch(bool switchFlag) const;
    void GetTouchpadPinchSwitch(bool &switchFlag) const;
    int32_t SetTouchpadSwipeSwitch(bool switchFlag) const;
    void GetTouchpadSwipeSwitch(bool &switchFlag) const;
    int32_t SetTouchpadRotateSwitch(bool rotateSwitch) const;
    void GetTouchpadRotateSwitch(bool &rotateSwitch) const;
    std::shared_ptr<PointerEvent> GetPointerEvent(int32_t deviceId);
    int32_t SetTouchpadThreeFingersTapSwitch(bool switchFlag) const;
    int32_t GetTouchpadThreeFingersTapSwitch(bool &switchFlag) const;

private:
    std::shared_ptr<TransformProcessor> MakeTransformProcessor(
        int32_t deviceId, DeviceType deviceType) const;

private:
    std::map<int32_t, std::shared_ptr<TransformProcessor>> processors_;
};

#define TOUCH_EVENT_HDR ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_EVENT_NORMALIZE_H