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

#include "mouse_device_state.h"

#include "define_multimodal.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseDeviceState"

namespace OHOS {
namespace MMI {
MouseDeviceState::MouseDeviceState()
{
    mouseCoord_ = { 0, 0 };
}

MouseDeviceState::~MouseDeviceState() {}

int32_t MouseDeviceState::GetMouseCoordsX() const
{
    return mouseCoord_.physicalX;
}

int32_t MouseDeviceState::GetMouseCoordsY() const
{
    return mouseCoord_.physicalY;
}

void MouseDeviceState::SetMouseCoords(int32_t x, int32_t y)
{
    mouseCoord_.physicalX = x;
    mouseCoord_.physicalY = y;
}

bool MouseDeviceState::IsLeftBtnPressed()
{
    auto iter = mouseBtnState_.find(LIBINPUT_LEFT_BUTTON_CODE);
    if (iter == mouseBtnState_.end()) {
        return false;
    }
    return iter->second > 0;
}

void MouseDeviceState::GetPressedButtons(std::vector<int32_t>& pressedButtons)
{
    for (const auto &item : mouseBtnState_) {
        if (item.second > 0) {
            pressedButtons.push_back(LibinputChangeToPointer(item.first));
        }
    }
}

void MouseDeviceState::MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState)
{
    std::map<uint32_t, int32_t>::iterator iter = mouseBtnState_.find(btnCode);
    if (iter == mouseBtnState_.end()) {
        auto ret = mouseBtnState_.insert(std::make_pair(btnCode, ((btnState == BUTTON_STATE_PRESSED) ? 1 : 0)));
        if (!ret.second) {
            MMI_HILOGE("Insert value failed, btnCode:%{public}d", btnCode);
        }
        return;
    }
    ChangeMouseState(btnState, iter->second);
}

int32_t MouseDeviceState::LibinputChangeToPointer(const uint32_t keyValue)
{
    auto it = mapLibinputChangeToPointer.find(keyValue);
    if (it == mapLibinputChangeToPointer.end()) {
        return PointerEvent::BUTTON_NONE;
    }
    return it->second;
}

void MouseDeviceState::ChangeMouseState(const BUTTON_STATE btnState, int32_t &btnStateCount)
{
    if (btnState == BUTTON_STATE_PRESSED) {
        btnStateCount++;
    } else if (btnState == BUTTON_STATE_RELEASED) {
        btnStateCount--;
    }
    if (btnStateCount > mouseBtnMax) {
        btnStateCount = mouseBtnMax;
    } else if (btnStateCount < 0) {
        btnStateCount = 0;
    }
}
} // namespace MMI
} // namespace OHOS