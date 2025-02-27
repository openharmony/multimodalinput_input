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

#ifndef MOUSE_EVENT_NORMALIZE_H
#define MOUSE_EVENT_NORMALIZE_H

#include "mouse_transform_processor.h"

namespace OHOS {
namespace MMI {
class MouseEventNormalize final : public std::enable_shared_from_this<MouseEventNormalize> {
    DECLARE_DELAYED_SINGLETON(MouseEventNormalize);
public:
    DISALLOW_COPY_AND_MOVE(MouseEventNormalize);
    std::shared_ptr<PointerEvent> GetPointerEvent();
    std::shared_ptr<PointerEvent> GetPointerEvent(int32_t deviceId);
    int32_t OnEvent(struct libinput_event *event);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    int32_t NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle);
    bool CheckAndPackageAxisEvent(libinput_event* event);
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    bool CheckFilterMouseEvent(struct libinput_event *event);
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool NormalizeMoveMouse(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t SetMouseScrollRows(int32_t rows);
    int32_t GetMouseScrollRows() const;
    int32_t SetMousePrimaryButton(int32_t primaryButton);
    int32_t GetMousePrimaryButton() const;
    int32_t SetPointerSpeed(int32_t speed);
    int32_t GetPointerSpeed() const;
    void OnDisplayLost(int32_t displayId);
    int32_t GetDisplayId() const;
    int32_t SetPointerLocation(int32_t x, int32_t y, int32_t dispiayId);
    int32_t SetTouchpadScrollSwitch(int32_t pid, bool switchFlag) const;
    void GetTouchpadScrollSwitch(bool &switchFlag) const;
    int32_t SetTouchpadScrollDirection(bool state) const;
    void GetTouchpadScrollDirection(bool &state) const;
    int32_t SetTouchpadTapSwitch(bool switchFlag) const;
    void GetTouchpadTapSwitch(bool &switchFlag) const;
    int32_t SetTouchpadRightClickType(int32_t type) const;
    void GetTouchpadRightClickType(int32_t &type) const;
    int32_t SetTouchpadPointerSpeed(int32_t speed) const;
    void GetTouchpadPointerSpeed(int32_t &speed) const;
    void GetTouchpadCDG(TouchpadCDG &touchpadCDG) const;

private:
    std::shared_ptr<MouseTransformProcessor> GetProcessor(int32_t deviceId) const;
    std::shared_ptr<MouseTransformProcessor> GetCurrentProcessor() const;
    void SetCurrentDeviceId(int32_t deviceId);
    int32_t GetCurrentDeviceId() const;

private:
    int32_t buttonId_ { -1 };
    bool isPressed_ { false };
    std::map<int32_t, std::shared_ptr<MouseTransformProcessor>> processors_;
    int32_t currentDeviceId_ { -1 };
};
#define MouseEventHdr ::OHOS::DelayedSingleton<MouseEventNormalize>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_EVENT_NORMALIZE_H