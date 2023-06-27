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

#ifndef TOUCHPAD_TRANSFORM_PROCESSOR_H
#define TOUCHPAD_TRANSFORM_PROCESSOR_H

#include "nocopyable.h"
#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class TouchPadTransformProcessor final : public TransformProcessor {
public:
    explicit TouchPadTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(TouchPadTransformProcessor);
    ~TouchPadTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;

    static int32_t SetTouchpadPinchSwitch(bool switchFlag);
    static int32_t GetTouchpadPinchSwitch(bool &switchFlag);
    static int32_t SetTouchpadSwipeSwitch(bool switchFlag);
    static int32_t GetTouchpadSwipeSwitch(bool &switchFlag);

private:
    static int32_t PutConfigDataToDatabase(std::string &key, bool value);
    static int32_t GetConfigDataFromDatabase(std::string &key, bool &value);

    void OnEventTouchPadDown(struct libinput_event *event);
    void OnEventTouchPadMotion(struct libinput_event *event);
    void OnEventTouchPadUp(struct libinput_event *event);
    void SetTouchPadSwipeData(struct libinput_event *event, int32_t action);
    void SetTouchPadPinchData(struct libinput_event *event, int32_t action);
    void OnEventTouchPadSwipeBegin(struct libinput_event *event);
    void OnEventTouchPadSwipeUpdate(struct libinput_event *event);
    void OnEventTouchPadSwipeEnd(struct libinput_event *event);
    void OnEventTouchPadPinchBegin(struct libinput_event *event);
    void OnEventTouchPadPinchUpdate(struct libinput_event *event);
    void OnEventTouchPadPinchEnd(struct libinput_event *event);

    int32_t GetTouchPadToolType(struct libinput_event_touch *data, struct libinput_device *device);
    int32_t GetTouchPadToolType(struct libinput_device *device);
    void InitToolType();
private:
    const int32_t deviceId_ { -1 };
    const int32_t defaultPointerId { 0 };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::vector<std::pair<int32_t, int32_t>> vecToolType_;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCHPAD_TRANSFORM_PROCESSOR_H