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

#include "mouse_state_gesture.h"

OHOS::MMI::MouseDeviceState::MouseDeviceState()
{
    mouseCoords = {0, 0};
}

OHOS::MMI::MouseDeviceState::~MouseDeviceState() { }

double OHOS::MMI::MouseDeviceState::GetMouseCoordsX()
{
    return this->mouseCoords.x;
}
double OHOS::MMI::MouseDeviceState::GetMouseCoordsY()
{
    return this->mouseCoords.y;
}

void OHOS::MMI::MouseDeviceState::SetMouseCoords(const double x, const double y)
{
    this->mouseCoords.x = x;
    this->mouseCoords.y = y;
}

bool OHOS::MMI::MouseDeviceState::IsLiftBtnPressed()
{
    std::lock_guard<std::mutex> lock(mu_);
    auto iter = this->mapCountState.find(LIBINPUT_LEFT_BUTTON_CODE);
    if (iter != this->mapCountState.end()) {
        if (iter->second > 0) {
            return true;
        }
    }
    return false;
}

void OHOS::MMI::MouseDeviceState::GetPressedButtons(std::vector<uint32_t>& pressedButtons)
{
    std::lock_guard<std::mutex> lock(mu_);
    if (!this->mapCountState.empty()) {
        for (auto iter : this->mapCountState) {
            if (iter.second > 0) {
                pressedButtons.push_back(LibinputChangeToPointer(iter.first));
            }
        }
    }
}

std::map<int16_t, uint32_t> OHOS::MMI::MouseDeviceState::GetCountState()
{
    return this->mapCountState;
}

void OHOS::MMI::MouseDeviceState::CountState(int16_t btnCode, uint32_t btnState)
{
    std::lock_guard<std::mutex> lock(mu_);
    std::map<int16_t, uint32_t>::iterator iter = this->mapCountState.find(btnCode);
    if (iter != this->mapCountState.end()) {
        ChangeMouseState(iter->second, btnState);
    } else {
        this->mapCountState.insert(std::make_pair(btnCode, ((btnState == BUTTON_STATE_PRESSED) ? 1 : 0)));
    }
}
int16_t OHOS::MMI::MouseDeviceState::LibinputChangeToPointer(int16_t keyValue)
{
    auto it = mapLibinputChangeToPointer.find(keyValue);
    if (it != mapLibinputChangeToPointer.end()) {
        return it->second;
    } else {
        return 0;
    }
}

void OHOS::MMI::MouseDeviceState::ChangeMouseState(uint32_t &stateValue, uint32_t btnState)
{
    if (btnState == BUTTON_STATE_PRESSED) {
        stateValue++;
    } else if (btnState == BUTTON_STATE_RELEASED) {
        stateValue--;
    }
    CheckMouseState(stateValue);
}

void OHOS::MMI::MouseDeviceState::CheckMouseState(uint32_t &stateValue)
{
    const int mouseBtnMax = 8; // 鼠标按键最多为8个
    if (stateValue > mouseBtnMax) {
        stateValue = mouseBtnMax;
    } else if (stateValue < 0) {
        stateValue = 0;
    }
}