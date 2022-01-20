/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOUSE_STATE_GESTURE_H
#define OHOS_MOUSE_STATE_GESTURE_H

#include "pointer_event.h"
#include "struct_multimodal.h"
#include "singleton.h"
#include <map>
#include <mutex>

namespace OHOS::MMI {
    class MouseDeviceState : public DelayedSingleton<MouseDeviceState> {
    public:
        enum LIBINPUT_BUTTON_CODE {
            LIBINPUT_LEFT_BUTTON_CODE = 272,
            LIBINPUT_RIGHT_BUTTON_CODE,
            LIBINPUT_MIDDLE_BUTTON_CODE,
        };

        const std::map<uint32_t, uint32_t> mapLibinputChangeToPointer = {
            {LIBINPUT_LEFT_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_LEFT},
            {LIBINPUT_RIGHT_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_RIGHT},
            {LIBINPUT_MIDDLE_BUTTON_CODE, PointerEvent::MOUSE_BUTTON_MIDDLE}
        };
    public:
        MouseDeviceState();
        ~MouseDeviceState();

        double GetMouseCoordsX();
        double GetMouseCoordsY();
        void SetMouseCoords(const double x, const double y);
        bool IsLiftBtnPressed();
        void GetPressedButtons(std::vector<uint32_t>& pressedButtons);
        std::map<int16_t, uint32_t> GetCountState();
        void CountState(int16_t btnCode, uint32_t btnState);

    private:
        int16_t LibinputChangeToPointer(int16_t keyValue);
        void ChangeMouseState(uint32_t &stateValue, uint32_t btnState);
        void CheckMouseState(uint32_t &stateValue);

    private:
        std::mutex mu_;
        DeviceCoords mouseCoords;
        std::map<int16_t, uint32_t> mapCountState;
    };
}

#define MouseState OHOS::MMI::MouseDeviceState::GetInstance()
#endif