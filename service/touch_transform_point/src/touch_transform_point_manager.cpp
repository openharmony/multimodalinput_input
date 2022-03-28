/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "touch_transform_point_manager.h"

#include "input_device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "TouchTransformPointManager" };
} // namespace

std::shared_ptr<PointerEvent> TouchTransformPointManager::OnLibInput(
    struct libinput_event *event, INPUT_DEVICE_TYPE deviceType)
{
    switch (deviceType) {
        case INPUT_DEVICE_CAP_TOUCH:
            return OnLibinputTouchEvent(event);
        case INPUT_DEVICE_CAP_TOUCH_PAD:
            return OnLibinputTouchPadEvent(event);
        case INPUT_DEVICE_CAP_GESTURE:
            return OnTouchPadGestrueEvent(event);
        default:
            MMI_HILOGE("The in parameter deviceType is error, deviceType:%{public}d", deviceType);
            break;
    }
    return nullptr;
}

std::shared_ptr<PointerEvent> TouchTransformPointManager::OnLibinputTouchEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto device = libinput_event_get_device(event);
    CHKPP(device);
    std::shared_ptr<TouchTransformPointProcessor> processor = nullptr;
    auto deviceId = InputDevMgr->FindInputDeviceId(device);
    if (auto it = touchPro_.find(deviceId); it != touchPro_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<TouchTransformPointProcessor>(deviceId);
        CHKPP(processor);
        processor->SetPointEventSource(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
        auto iter = touchPro_.insert(
            std::pair<int32_t, std::shared_ptr<TouchTransformPointProcessor>>(deviceId, processor));
        if (!iter.second) {
            MMI_HILOGE("Insert value failed, touch device:%{public}d", deviceId);
        }
    }
    return processor->OnLibinputTouchEvent(event);
}

std::shared_ptr<PointerEvent> TouchTransformPointManager::OnLibinputTouchPadEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto device = libinput_event_get_device(event);
    CHKPP(device);
    std::shared_ptr<TouchPadTransformPointProcessor> processor = nullptr;
    auto deviceId = InputDevMgr->FindInputDeviceId(device);
    auto it = touchpadPro_.find(deviceId);
    if (it != touchpadPro_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<TouchPadTransformPointProcessor>(deviceId);
        CHKPP(processor);
        processor->SetPointEventSource(PointerEvent::SOURCE_TYPE_TOUCHPAD);
        auto iter = touchpadPro_.insert(
            std::pair<int32_t, std::shared_ptr<TouchPadTransformPointProcessor>>(deviceId, processor));
        if (!iter.second) {
            MMI_HILOGE("Insert value failed, touchpad device:%{public}d", deviceId);
        }
    }
    return processor->OnLibinputTouchPadEvent(event);
}

std::shared_ptr<PointerEvent> TouchTransformPointManager::OnTouchPadGestrueEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto device = libinput_event_get_device(event);
    CHKPP(device);
    std::shared_ptr<GestureTransformPointProcessor> processor = nullptr;
    auto deviceId = InputDevMgr->FindInputDeviceId(device);
    auto it = gesturePro_.find(deviceId);
    if (it != gesturePro_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<GestureTransformPointProcessor>(deviceId);
        CHKPP(processor);
        processor->SetPointEventSource(PointerEvent::SOURCE_TYPE_MOUSE);
        auto iter = gesturePro_.insert(
            std::pair<int32_t, std::shared_ptr<GestureTransformPointProcessor>>(deviceId, processor));
        if (!iter.second) {
            MMI_HILOGE("Insert value failed, gesture device:%{public}d", deviceId);
        }
    }
    return processor->OnTouchPadGestrueEvent(event);
}
} // namespace MMI
} // namespace OHOS
