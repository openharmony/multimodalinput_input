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

#include "touch_transform_point_manager.h"
#include "input_device_manager.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "TouchTransformPointManager" };
    }

std::shared_ptr<PointerEvent> TouchTransformPointManager::OnLibinputTouchEvent(libinput_event *event)
{
    CHKR(event, PARAM_INPUT_INVALID, nullptr);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
        MMI_LOGT("This touch event is canceled type:%{public}d", type); 
        return nullptr;
    }
    auto device = libinput_event_get_device(event);
    CHKR(device, ERROR_NULL_POINTER, nullptr);
    std::shared_ptr<TouchTransformPointProcessor> processor;
    auto deviceId = inputDeviceManager->FindInputDeviceId(device);
    auto it = touchPro_.find(deviceId);
    if (it != touchPro_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<TouchTransformPointProcessor>(deviceId);
        processor->SetPointEventSource(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
        touchPro_.insert(std::pair<int32_t, std::shared_ptr<TouchTransformPointProcessor>>(deviceId, processor));
    }
    return processor->OnLibinputTouchEvent(event);
}

std::shared_ptr<PointerEvent> TouchTransformPointManager::OnLibinputTouchPadEvent(libinput_event *event)
{
    CHKR(event, PARAM_INPUT_INVALID, nullptr);
    auto device = libinput_event_get_device(event);
    CHKR(device, ERROR_NULL_POINTER, nullptr);
    std::shared_ptr<TouchPadTransformPointProcessor> processor;
    auto deviceId = inputDeviceManager->FindInputDeviceId(device);
    auto it = touchpadPro_.find(deviceId);
    if (it != touchpadPro_.end()) {
        processor = it->second;
    } else {
        processor = std::make_shared<TouchPadTransformPointProcessor>(deviceId);
        processor->SetPointEventSource(PointerEvent::SOURCE_TYPE_TOUCHPAD);
        touchpadPro_.insert(std::pair<int32_t, std::shared_ptr<TouchPadTransformPointProcessor>>(deviceId, processor));
    }
    return processor->OnLibinputTouchPadEvent(event);
}
}
