/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "mouse_event_normalize.h"
#include "mouse_device_state.h"

#include "input_device_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseEventNormalize"

namespace OHOS {
namespace MMI {

void MouseEventNormalize::OnDeviceAdded(int32_t deviceId)
{
    CALL_INFO_TRACE;
    CHKPV(env_);
    auto devMgr = env_->GetDeviceManager();
    if (devMgr == nullptr) {
        MMI_HILOGE("No device manager");
        return;
    }
    devMgr->ForDevice(deviceId,
        [this, deviceId](const IInputDeviceManager::IInputDevice &dev) {
            auto inputDev = dev.GetRawDevice();
            if (inputDev == nullptr) {
                MMI_HILOGE("No raw device attached to device(%{private}d)", deviceId);
                return;
            }
            if (!dev.IsMouse()) {
                MMI_HILOGI("[%{public}s:%{private}d] Not pointer device", dev.GetName().c_str(), deviceId);
                return;
            }
            if (auto iter = processors_.find(deviceId); iter != processors_.end()) {
                MMI_HILOGW("Dirty processor attached to device(%{public}d)", deviceId);
                return;
            }
            processors_.emplace(deviceId, std::make_shared<MouseTransformProcessor>(env_, deviceId));
            MMI_HILOGI("Emplace processor for device(%{public}d)", deviceId);
        });
}

void MouseEventNormalize::OnDeviceRemoved(int32_t deviceId)
{
    CALL_INFO_TRACE;
    auto iter = std::find_if(processors_.cbegin(), processors_.cend(),
        [deviceId](const auto &item) {
            return ((item.first == deviceId));
        });
    if (iter != processors_.end()) {
        MMI_HILOGI("Clear processor attached to device(%{public}d)", deviceId);
        processors_.erase(iter);
    }
}

bool MouseEventNormalize::HasMouse()
{
    return !processors_.empty();
}

MouseEventNormalize::MouseEventNormalize(IInputServiceContext *env) : env_(env) { }

MouseEventNormalize::~MouseEventNormalize() { }

std::shared_ptr<MouseTransformProcessor> MouseEventNormalize::GetProcessor(int32_t deviceId) const
{
    auto iter = processors_.find(deviceId);
    if (iter == processors_.end()) {
        MMI_HILOGE("Can't find mouse processor by deviceId:%{public}d", deviceId);
        return nullptr;
    }
    return iter->second;
}

std::shared_ptr<MouseTransformProcessor> MouseEventNormalize::GetCurrentProcessor() const
{
    int32_t deviceId = GetCurrentDeviceId();
    auto iter = processors_.find(deviceId);
    if (iter == processors_.end()) {
        MMI_HILOGE("Can't find mouse processor by deviceId:%{public}d", deviceId);
        return nullptr;
    }
    return iter->second;
}

void MouseEventNormalize::SetCurrentDeviceId(int32_t deviceId)
{
    currentDeviceId_ = deviceId;
}

int32_t MouseEventNormalize::GetCurrentDeviceId() const
{
    return currentDeviceId_;
}

std::shared_ptr<PointerEvent> MouseEventNormalize::GetPointerEvent()
{
    auto processor = GetCurrentProcessor();
    CHKPP(processor);
    return processor->GetPointerEvent();
}

std::shared_ptr<PointerEvent> MouseEventNormalize::GetPointerEvent(int32_t deviceId)
{
    auto iter = processors_.find(deviceId);
    if (iter == processors_.end()) {
        MMI_HILOGE("Can't find mouse processor by deviceId:%{public}d", deviceId);
        return nullptr;
    }
    CHKPP(iter->second);
    return iter->second->GetPointerEvent();
}

int32_t MouseEventNormalize::OnEvent(struct libinput_event *event)
{
    CHKPR(event, RET_ERR);
    auto device = libinput_event_get_device(event);
    CHKPR(device, RET_ERR);
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return RET_ERR;
    }
    auto devMgr = env_->GetDeviceManager();
    if (devMgr == nullptr) {
        MMI_HILOGE("No device manager");
        return RET_ERR;
    }
    int32_t deviceId = devMgr->FindInputDeviceId(device);
    if (deviceId < 0) {
        MMI_HILOGE("The deviceId:%{public}d is invalid", deviceId);
        return RET_ERR;
    }
    SetCurrentDeviceId(deviceId);
    std::shared_ptr<MouseTransformProcessor> processor { nullptr };
    if (auto it = processors_.find(deviceId); it != processors_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<MouseTransformProcessor>(env_, deviceId);
        [[ maybe_unused ]] auto [tIter, isOk] = processors_.emplace(deviceId, processor);
    }
    CHKPR(processor, RET_ERR);
    return processor->Normalize(event);
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
void MouseEventNormalize::OnDisplayLost(int32_t displayId)
{
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return;
    }
    MouseTransformProcessor::OnDisplayLost(*env_, displayId);
}

int32_t MouseEventNormalize::GetDisplayId() const
{
    if (env_ == nullptr) {
        return RET_ERR;
    }
    return MouseTransformProcessor::GetDisplayId(*env_);
}

bool MouseEventNormalize::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    auto processor = GetCurrentProcessor();
    CHKPF(processor);
    return processor->NormalizeMoveMouse(offsetX, offsetY);
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void MouseEventNormalize::Dump(int32_t fd, const std::vector<std::string> &args)
{
    auto processor = GetCurrentProcessor();
    CHKPV(processor);
    processor->Dump(fd, args);
}

int32_t MouseEventNormalize::NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle)
{
    CHKPR(event, RET_ERR);
    auto device = libinput_event_get_device(event);
    CHKPR(device, RET_ERR);
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return RET_ERR;
    }
    auto devMgr = env_->GetDeviceManager();
    if (devMgr == nullptr) {
        MMI_HILOGE("No device manager");
        return RET_ERR;
    }
    int32_t deviceId = devMgr->FindInputDeviceId(device);
    if (deviceId < 0) {
        MMI_HILOGE("The deviceId is invalid, deviceId:%{public}d", deviceId);
        return RET_ERR;
    }
    SetCurrentDeviceId(deviceId);
    std::shared_ptr<MouseTransformProcessor> processor { nullptr };
    if (auto it = processors_.find(deviceId); it != processors_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<MouseTransformProcessor>(env_, deviceId);
        [[ maybe_unused ]] auto [tIter, isOk] = processors_.emplace(deviceId, processor);
    }
    CHKPR(processor, RET_ERR);
    return processor->NormalizeRotateEvent(event, type, angle);
}

bool MouseEventNormalize::CheckAndPackageAxisEvent(libinput_event* event)
{
    CHKPF(event);
    auto device = libinput_event_get_device(event);
    CHKPF(device);
    if (env_ == nullptr) {
        MMI_HILOGE("Env is nullptr");
        return false;
    }
    auto devMgr = env_->GetDeviceManager();
    if (devMgr == nullptr) {
        MMI_HILOGE("No device manager");
        return false;
    }
    int32_t deviceId = devMgr->FindInputDeviceId(device);
    if (deviceId < 0) {
        MMI_HILOGE("The deviceId is invalid, deviceId:%{public}d", deviceId);
        return RET_ERR;
    }
    SetCurrentDeviceId(deviceId);
    std::shared_ptr<MouseTransformProcessor> processor { nullptr };
    if (auto it = processors_.find(deviceId); it != processors_.end()) {
        processor = it->second;
    }
    CHKPF(processor);
    return processor->CheckAndPackageAxisEvent();
}

int32_t MouseEventNormalize::SetMouseScrollRows(int32_t rows)
{
    return MouseTransformProcessor::SetMouseScrollRows(rows);
}

int32_t MouseEventNormalize::GetMouseScrollRows() const
{
    return MouseTransformProcessor::GetMouseScrollRows();
}

int32_t MouseEventNormalize::SetMousePrimaryButton(int32_t primaryButton)
{
    return MouseTransformProcessor::SetMousePrimaryButton(primaryButton);
}

int32_t MouseEventNormalize::GetMousePrimaryButton() const
{
    return MouseTransformProcessor::GetMousePrimaryButton();
}

int32_t MouseEventNormalize::SetPointerSpeed(int32_t speed)
{
    return MouseTransformProcessor::SetPointerSpeed(speed);
}

int32_t MouseEventNormalize::GetPointerSpeed() const
{
    return MouseTransformProcessor::GetPointerSpeed();
}

int32_t MouseEventNormalize::SetPointerLocation(int32_t x, int32_t y, int32_t displayId)
{
    return MouseTransformProcessor::SetPointerLocation(x, y, displayId);
}

int32_t MouseEventNormalize::GetPointerLocation(int32_t &displayId, double &displayX, double &displayY)
{
    return MouseTransformProcessor::GetPointerLocation(displayId, displayX, displayY);
}

int32_t MouseEventNormalize::SetTouchpadScrollSwitch(int32_t pid, bool switchFlag) const
{
    return MouseTransformProcessor::SetTouchpadScrollSwitch(pid, switchFlag);
}

void MouseEventNormalize::GetTouchpadScrollSwitch(bool &switchFlag) const
{
    MouseTransformProcessor::GetTouchpadScrollSwitch(switchFlag);
}

int32_t MouseEventNormalize::SetTouchpadScrollDirection(bool state) const
{
    return MouseTransformProcessor::SetTouchpadScrollDirection(state);
}

void MouseEventNormalize::GetTouchpadScrollDirection(bool &switchFlag) const
{
    MouseTransformProcessor::GetTouchpadScrollDirection(switchFlag);
}

int32_t MouseEventNormalize::SetTouchpadTapSwitch(bool switchFlag) const
{
    return MouseTransformProcessor::SetTouchpadTapSwitch(switchFlag);
}

void MouseEventNormalize::GetTouchpadTapSwitch(bool &switchFlag) const
{
    MouseTransformProcessor::GetTouchpadTapSwitch(switchFlag);
}

int32_t MouseEventNormalize::SetTouchpadPointerSpeed(int32_t speed) const
{
    return MouseTransformProcessor::SetTouchpadPointerSpeed(speed);
}

void MouseEventNormalize::GetTouchpadPointerSpeed(int32_t &speed) const
{
    MouseTransformProcessor::GetTouchpadPointerSpeed(speed);
}

void MouseEventNormalize::GetTouchpadCDG(TouchpadCDG &touchpadCDG) const
{
    MouseTransformProcessor::GetTouchpadCDG(touchpadCDG);
}

int32_t MouseEventNormalize::SetTouchpadRightClickType(int32_t type) const
{
    return MouseTransformProcessor::SetTouchpadRightClickType(type);
}

void MouseEventNormalize::GetTouchpadRightClickType(int32_t &type) const
{
    MouseTransformProcessor::GetTouchpadRightClickType(type);
}

#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
bool MouseEventNormalize::CheckFilterMouseEvent(struct libinput_event *event)
{
    auto processor = GetCurrentProcessor();
    CHKPF(processor);
    return processor->CheckFilterMouseEvent(event);
}
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE

int32_t MouseEventNormalize::SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable)
{
    std::shared_ptr<MouseTransformProcessor> processor { nullptr };
    if (auto it = processors_.find(deviceId); it != processors_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<MouseTransformProcessor>(env_, deviceId);
        [[ maybe_unused ]] auto [tIter, isOk] = processors_.emplace(deviceId, processor);
    }
    CHKPR(processor, RET_ERR);
    processor->SetMouseAccelerateMotionSwitch(enable);
    return RET_OK;
}

int32_t MouseEventNormalize::GetMouseCoordsX() const
{
    return MouseState->GetMouseCoordsX();
}

int32_t MouseEventNormalize::GetMouseCoordsY() const
{
    return MouseState->GetMouseCoordsY();
}

void MouseEventNormalize::SetMouseCoords(int32_t x, int32_t y)
{
   MouseState->SetMouseCoords(x, y);
}

bool MouseEventNormalize::IsLeftBtnPressed()
{
    return MouseState->IsLeftBtnPressed();
}

void MouseEventNormalize::GetPressedButtons(std::vector<int32_t>& pressedButtons)
{
   MouseState->GetPressedButtons(pressedButtons);
}

void MouseEventNormalize::MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState)
{
   MouseState->MouseBtnStateCounts(btnCode, btnState);
}

int32_t MouseEventNormalize::LibinputChangeToPointer(const uint32_t keyValue)
{
    return MouseState->LibinputChangeToPointer(keyValue);
}

int32_t MouseEventNormalize::SetPointerSpeed(int32_t speed)
{
    MouseTransformProcessor::SetPointerSpeed(speed);
    return RET_OK;
}

int32_t MouseEventNormalize::SetScrollSwitchSetterPid(int32_t pid)
{
    MouseTransformProcessor::SetScrollSwitchSetterPid(pid);
    return RET_OK;
}

extern "C" IMouseEventNormalize* CreateInstance(IInputServiceContext *env)
{
    return new MouseEventNormalize(env);
}

extern "C" void DestroyInstance(IMouseEventNormalize *instance)
{
    if (instance != nullptr) {
        delete instance;
    }
}
} // namespace MMI
} // namespace OHOS
