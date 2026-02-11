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

#ifndef MOUSE_EVENT_NORMALIZE_H
#define MOUSE_EVENT_NORMALIZE_H

#include "device_observer.h"
#include "mouse_transform_processor.h"
#include "i_mouse_event_normalizer.h"
#include "i_input_service_context.h"

namespace OHOS {
namespace MMI {
class MouseEventNormalize final : public IMouseEventNormalize {
public:
    explicit MouseEventNormalize(IInputServiceContext *env);
    ~MouseEventNormalize();
public:
    DISALLOW_COPY_AND_MOVE(MouseEventNormalize);
    void OnDeviceAdded(int32_t deviceId) override;
    void OnDeviceRemoved(int32_t deviceId) override;
    bool HasMouse() override;
    int32_t OnEvent(struct libinput_event *event) override;

    std::shared_ptr<PointerEvent> GetPointerEvent() override;
    std::shared_ptr<PointerEvent> GetPointerEvent(int32_t deviceId) override;
    void Dump(int32_t fd, const std::vector<std::string> &args) override;
    int32_t NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle) override;
    bool CheckAndPackageAxisEvent(libinput_event* event) override;
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    bool CheckFilterMouseEvent(struct libinput_event *event) override;
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool NormalizeMoveMouse(int32_t offsetX, int32_t offsetY) override;
    void OnDisplayLost(int32_t displayId) override;
    int32_t GetDisplayId() const override;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t SetPointerLocation(int32_t x, int32_t y, int32_t displayId = -1) override;
    int32_t GetPointerLocation(int32_t &displayId, double &displayX, double &displayY) override;
    int32_t SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable) override;

    // MouseDeviceState Interface
    int32_t GetMouseCoordsX() const override;
    int32_t GetMouseCoordsY() const override;
    void SetMouseCoords(int32_t x, int32_t y) override;
    bool IsLeftBtnPressed() override;
    void GetPressedButtons(std::vector<int32_t>& pressedButtons) override;
    void MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState) override;
    int32_t LibinputChangeToPointer(const uint32_t keyValue) override;
    int32_t SetScrollSwitchSetterPid(int32_t pid) override;

private:
    std::shared_ptr<MouseTransformProcessor> GetProcessor(int32_t deviceId) const;
    std::shared_ptr<MouseTransformProcessor> GetCurrentProcessor() const;
    void SetCurrentDeviceId(int32_t deviceId);
    int32_t GetCurrentDeviceId() const;

private:
    int32_t buttonId_ { -1 };
    int32_t currentDeviceId_ { -1 };
    bool isPressed_ { false };
    std::map<int32_t, std::shared_ptr<MouseTransformProcessor>> processors_;
    std::shared_ptr<IDeviceObserver> inputDevObserver_;
    IInputServiceContext *env_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_EVENT_NORMALIZE_H