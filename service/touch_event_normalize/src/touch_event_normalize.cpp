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

#include "touch_event_normalize.h"

#ifndef OHOS_BUILD_ENABLE_WATCH
#include "gesture_transform_processor.h"
#endif // OHOS_BUILD_ENABLE_WATCH
#include "input_device_manager.h"
#ifdef OHOS_BUILD_ENABLE_TOUCH
#ifndef OHOS_BUILD_ENABLE_WATCH
#include "tablet_tool_tranform_processor.h"
#endif // OHOS_BUILD_ENABLE_WATCH
#include "touch_transform_processor.h"
#include "remote_control_transform_processor.h"
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
#include "touchpad_transform_processor.h"
#endif // OHOS_BUILD_ENABLE_POINTER

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchEventNormalize"

namespace OHOS {
namespace MMI {
void TouchEventNormalize::InputDeviceObserver::OnDeviceRemoved(int32_t deviceId)
{
    TOUCH_EVENT_HDR->OnDeviceRemoved(deviceId);
}

TouchEventNormalize::TouchEventNormalize()
{
    SetUpDeviceObserver();
}

TouchEventNormalize::~TouchEventNormalize()
{
    TearDownDeviceObserver();
}

std::shared_ptr<PointerEvent> TouchEventNormalize::OnLibInput(struct libinput_event *event, DeviceType deviceType)
{
    CHKPP(event);
    auto device = libinput_event_get_device(event);
    CHKPP(device);
    std::shared_ptr<TransformProcessor> processor{ nullptr };
    auto deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    if (deviceType == TouchEventNormalize::DeviceType::TOUCH_PAD) {
        if (auto it = touchpad_processors_.find(deviceId); it != touchpad_processors_.end()) {
            processor = it->second;
        } else {
            processor = MakeTransformProcessor(deviceId, deviceType);
            CHKPP(processor);
            auto [tIter, isOk] = touchpad_processors_.emplace(deviceId, processor);
            if (!isOk) {
                MMI_HILOGE("Duplicate device record:%{public}d", deviceId);
            }
        }
    } else if (deviceType == TouchEventNormalize::DeviceType::REMOTE_CONTROL) {
        if (auto it = remote_control_processors_.find(deviceId); it != remote_control_processors_.end()) {
            processor = it->second;
        } else {
            processor = MakeTransformProcessor(deviceId, deviceType);
            CHKPP(processor);
            auto [tIter, isOk] = remote_control_processors_.emplace(deviceId, processor);
            if (!isOk) {
                MMI_HILOGE("Duplicate device record:%{public}d", deviceId);
            }
        }
    } else {
        if (auto it = processors_.find(deviceId); it != processors_.end()) {
            processor = it->second;
        } else {
            processor = MakeTransformProcessor(deviceId, deviceType);
            CHKPP(processor);
            auto [tIter, isOk] = processors_.emplace(deviceId, processor);
            if (!isOk) {
                MMI_HILOGE("Duplicate device record:%{public}d", deviceId);
            }
        }
    }
    return processor->OnEvent(event);
}

#ifndef OHOS_BUILD_ENABLE_WATCH
std::shared_ptr<TransformProcessor> TouchEventNormalize::MakeTransformProcessor(int32_t deviceId,
    DeviceType deviceType) const
{
    std::shared_ptr<TransformProcessor> processor{ nullptr };
    switch (deviceType) {
#ifdef OHOS_BUILD_ENABLE_TOUCH
        case DeviceType::TOUCH: {
            processor = std::make_shared<TouchTransformProcessor>(deviceId);
            break;
        }
        case DeviceType::TABLET_TOOL: {
            processor = std::make_shared<TabletToolTransformProcessor>(deviceId);
            break;
        }
        case DeviceType::REMOTE_CONTROL: {
            processor = std::make_shared<Remote_ControlTransformProcessor>(deviceId);
            break;
        }
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
        case DeviceType::TOUCH_PAD: {
            processor = std::make_shared<TouchPadTransformProcessor>(deviceId);
            break;
        }
        case DeviceType::GESTURE: {
            processor = std::make_shared<GestureTransformProcessor>(deviceId);
            break;
        }
#endif // OHOS_BUILD_ENABLE_POINTER
        default: {
            MMI_HILOGE("Unsupported device type:%{public}d", deviceType);
            break;
        }
    }
    return processor;
}
#else
std::shared_ptr<TransformProcessor> TouchEventNormalize::MakeTransformProcessor(int32_t deviceId,
    DeviceType deviceType) const
{
    std::shared_ptr<TransformProcessor> processor{ nullptr };
    switch (deviceType) {
#ifdef OHOS_BUILD_ENABLE_TOUCH
        case DeviceType::TOUCH: {
            processor = std::make_shared<TouchTransformProcessor>(deviceId);
            break;
        }
#endif // OHOS_BUILD_ENABLE_TOUCH
        default: {
            MMI_HILOGE("Unsupported device type:%{public}d", deviceType);
            break;
        }
    }
    return processor;
}
#endif //OHOS_BUILD_ENABLE_WATCH

std::shared_ptr<PointerEvent> TouchEventNormalize::GetPointerEvent(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    auto iter = processors_.find(deviceId);
    if (iter != processors_.end()) {
        CHKPP(iter->second);
        return iter->second->GetPointerEvent();
    }
    return nullptr;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t TouchEventNormalize::SetTouchpadPinchSwitch(bool switchFlag) const
{
    return TouchPadTransformProcessor::SetTouchpadPinchSwitch(switchFlag);
}

void TouchEventNormalize::GetTouchpadPinchSwitch(bool &switchFlag) const
{
    TouchPadTransformProcessor::GetTouchpadPinchSwitch(switchFlag);
}

int32_t TouchEventNormalize::SetTouchpadSwipeSwitch(bool switchFlag) const
{
    return TouchPadTransformProcessor::SetTouchpadSwipeSwitch(switchFlag);
}

void TouchEventNormalize::GetTouchpadSwipeSwitch(bool &switchFlag) const
{
    TouchPadTransformProcessor::GetTouchpadSwipeSwitch(switchFlag);
}

int32_t TouchEventNormalize::SetTouchpadRotateSwitch(bool rotateSwitch) const
{
    return TouchPadTransformProcessor::SetTouchpadRotateSwitch(rotateSwitch);
}

void TouchEventNormalize::GetTouchpadRotateSwitch(bool &rotateSwitch) const
{
    TouchPadTransformProcessor::GetTouchpadRotateSwitch(rotateSwitch);
}

int32_t TouchEventNormalize::SetTouchpadDoubleTapAndDragState(bool switchFlag) const
{
    return TouchPadTransformProcessor::SetTouchpadDoubleTapAndDragState(switchFlag);
}

void TouchEventNormalize::GetTouchpadDoubleTapAndDragState(bool &switchFlag) const
{
    TouchPadTransformProcessor::GetTouchpadDoubleTapAndDragState(switchFlag);
}

int32_t TouchEventNormalize::SetTouchpadScrollRows(int32_t rows)
{
    return TouchPadTransformProcessor::SetTouchpadScrollRows(rows);
}

int32_t TouchEventNormalize::GetTouchpadScrollRows() const
{
    return TouchPadTransformProcessor::GetTouchpadScrollRows();
}

int32_t TouchEventNormalize::SetTouchpadThreeFingersTapSwitch(bool switchFlag) const
{
    return TouchPadTransformProcessor::SetTouchpadThreeFingersTapSwitch(switchFlag);
}

int32_t TouchEventNormalize::GetTouchpadThreeFingersTapSwitch(bool &switchFlag) const
{
    return TouchPadTransformProcessor::GetTouchpadThreeFingersTapSwitch(switchFlag);
}
#endif // OHOS_BUILD_ENABLE_POINTER

void TouchEventNormalize::SetUpDeviceObserver()
{
    if (inputDevObserver_ == nullptr) {
        inputDevObserver_ = std::make_shared<InputDeviceObserver>();
        INPUT_DEV_MGR->Attach(inputDevObserver_);
    }
}

void TouchEventNormalize::TearDownDeviceObserver()
{
    if (inputDevObserver_ != nullptr) {
        INPUT_DEV_MGR->Detach(inputDevObserver_);
        inputDevObserver_ = nullptr;
    }
}

void TouchEventNormalize::OnDeviceRemoved(int32_t deviceId)
{
    if (auto iter = processors_.find(deviceId); iter != processors_.end()) {
        MMI_HILOGI("Clear processor attached to device(%{public}d)", deviceId);
        auto processor = iter->second;
        processors_.erase(iter);
        if (processor != nullptr) {
            processor->OnDeviceRemoved();
        }
    }
    if (auto iter = touchpad_processors_.find(deviceId); iter != touchpad_processors_.end()) {
        MMI_HILOGI("Clear touchpad processor attached to device(%{public}d)", deviceId);
        auto processor = iter->second;
        touchpad_processors_.erase(iter);
        if (processor != nullptr) {
            processor->OnDeviceRemoved();
        }
    }
    if (auto iter = remote_control_processors_.find(deviceId); iter != remote_control_processors_.end()) {
        MMI_HILOGI("Clear remote-control processor attached to device(%{public}d)", deviceId);
        auto processor = iter->second;
        remote_control_processors_.erase(iter);
        if (processor != nullptr) {
            processor->OnDeviceRemoved();
        }
    }
}
} // namespace MMI
} // namespace OHOS
