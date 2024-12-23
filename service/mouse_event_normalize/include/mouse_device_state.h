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

#ifndef MOUSE_DEVICE_STATE_H
#define MOUSE_DEVICE_STATE_H

#include <map>
#include <mutex>

#include "nocopyable.h"
#include "singleton.h"

#include "pointer_event.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
class MouseDeviceState final {
    DECLARE_DELAYED_SINGLETON(MouseDeviceState);
public:
    const int32_t mouseBtnMax = 8;
    enum LIBINPUT_BUTTON_CODE {
        LIBINPUT_LEFT_BUTTON_CODE = 272,
        LIBINPUT_RIGHT_BUTTON_CODE,
        LIBINPUT_MIDDLE_BUTTON_CODE,
        LIBINPUT_SIDE_BUTTON_CODE,
        LIBINPUT_EXTRA_BUTTON_CODE,
        LIBINPUT_FORWARD_BUTTON_CODE,
        LIBINPUT_BACK_BUTTON_CODE,
        LIBINPUT_TASK_BUTTON_CODE
    };
    struct MouseDeviceCoords {
        int32_t physicalX { 0 };
        int32_t physicalY { 0 };
    };
    const std::map<uint32_t, int32_t> mapLibinputChangeToPointer = {
#ifndef OHOS_BUILD_ENABLE_WATCH
        { LIBINPUT_LEFT_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_LEFT },
        { LIBINPUT_RIGHT_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_RIGHT },
        { LIBINPUT_MIDDLE_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_MIDDLE },
        { LIBINPUT_SIDE_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_SIDE },
        { LIBINPUT_EXTRA_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_EXTRA },
        { LIBINPUT_FORWARD_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_FORWARD },
        { LIBINPUT_BACK_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_BACK },
        { LIBINPUT_TASK_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_TASK },
#endif // OHOS_BUILD_ENABLE_WATCH
    };
public:
    DISALLOW_COPY_AND_MOVE(MouseDeviceState);
    int32_t GetMouseCoordsX() const;
    int32_t GetMouseCoordsY() const;
    void SetMouseCoords(int32_t x, int32_t y);
    bool IsLeftBtnPressed();
    void GetPressedButtons(std::vector<int32_t>& pressedButtons);
    void MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState);
    int32_t LibinputChangeToPointer(const uint32_t keyValue);

private:
    void ChangeMouseState(const BUTTON_STATE btnState, int32_t& btnStateCount);

private:
    MouseDeviceCoords mouseCoord_;
    std::map<uint32_t, int32_t> mouseBtnState_;
};

#define MouseState ::OHOS::DelayedSingleton<MouseDeviceState>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_DEVICE_STATE_H