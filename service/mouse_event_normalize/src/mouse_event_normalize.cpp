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

#include "mouse_event_normalize.h"

#include <cinttypes>

#include <linux/input-event-codes.h>

#include "define_multimodal.h"
#include "event_log_helper.h"
#include "i_input_windows_manager.h"
#include "i_pointer_drawing_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "mouse_device_state.h"
#include "timer_manager.h"
#include "util_ex.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseEventNormalize"

namespace OHOS {
namespace MMI {
MouseEventNormalize::MouseEventNormalize() {}
MouseEventNormalize::~MouseEventNormalize() {}

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
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    if (deviceId < 0) {
        MMI_HILOGE("The deviceId:%{public}d is invalid", deviceId);
        return RET_ERR;
    }
    SetCurrentDeviceId(deviceId);
    std::shared_ptr<MouseTransformProcessor> processor { nullptr };
    if (auto it = processors_.find(deviceId); it != processors_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<MouseTransformProcessor>(deviceId);
        [[ maybe_unused ]] auto [tIter, isOk] = processors_.emplace(deviceId, processor);
    }
    CHKPR(processor, RET_ERR);
    return processor->Normalize(event);
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
void MouseEventNormalize::OnDisplayLost(int32_t displayId)
{
    MouseTransformProcessor::OnDisplayLost(displayId);
}

int32_t MouseEventNormalize::GetDisplayId() const
{
    return MouseTransformProcessor::GetDisplayId();
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
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    if (deviceId < 0) {
        MMI_HILOGE("The deviceId is invalid, deviceId:%{public}d", deviceId);
        return RET_ERR;
    }
    SetCurrentDeviceId(deviceId);
    std::shared_ptr<MouseTransformProcessor> processor { nullptr };
    if (auto it = processors_.find(deviceId); it != processors_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<MouseTransformProcessor>(deviceId);
        [[ maybe_unused ]] auto [tIter, isOk] = processors_.emplace(deviceId, processor);
    }
    CHKPR(processor, RET_ERR);
    return processor->NormalizeRotateEvent(event, type, angle);
}

bool MouseEventNormalize::CheckAndPackageAxisEvent(libinput_event* event)
{
    CHKPF(event);
    auto device = libinput_event_get_device(event);
    CHKPR(device, RET_ERR);
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
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

int32_t MouseEventNormalize::SetPointerLocation(int32_t x, int32_t y)
{
    return MouseTransformProcessor::SetPointerLocation(x, y);
}

int32_t MouseEventNormalize::SetTouchpadScrollSwitch(bool switchFlag) const
{
    return MouseTransformProcessor::SetTouchpadScrollSwitch(switchFlag);
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

int32_t MouseEventNormalize::SetTouchpadRightClickType(int32_t type) const
{
    return MouseTransformProcessor::SetTouchpadRightClickType(type);
}

void MouseEventNormalize::GetTouchpadRightClickType(int32_t &type) const
{
    MouseTransformProcessor::GetTouchpadRightClickType(type);
}
} // namespace MMI
} // namespace OHOS
