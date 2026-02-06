/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MOUSE_EVENT_INTERFACE_H
#define MOUSE_EVENT_INTERFACE_H

#include <functional>
#include <memory>
#include <shared_mutex>

#include "component_manager.h"
#include "device_observer.h"
#include "i_mouse_event_normalizer.h"
#include "touchpad_control_display_gain.h"
#include "key_event.h"

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class MouseEventInterface final {
private:
    class InputDeviceObserver final : public IDeviceObserver {
    public:
        InputDeviceObserver(std::shared_ptr<MouseEventInterface> parent);
        ~InputDeviceObserver() override = default;
        DISALLOW_COPY_AND_MOVE(InputDeviceObserver);

        void OnDeviceAdded(int32_t deviceId) override;
        void OnDeviceRemoved(int32_t deviceId) override;
        void UpdatePointerDevice(bool hasPointerDevice, bool isVisible, bool isHotPlug) override {}

    private:
        std::weak_ptr<MouseEventInterface> parent_;
    };

public:
    static std::shared_ptr<MouseEventInterface> GetInstance();

    MouseEventInterface() = default;
    ~MouseEventInterface();
    DISALLOW_COPY_AND_MOVE(MouseEventInterface);

    void AttachInputServiceContext(std::shared_ptr<IInputServiceContext> env);
    void LoadMouseExplicitly();
    // MouseEventNormalize Interface
    bool HasMouse() ;
    int32_t OnEvent(struct libinput_event *event) ;
    std::shared_ptr<PointerEvent> GetPointerEvent();
    std::shared_ptr<PointerEvent> GetPointerEvent(int32_t deviceId) ;
    void Dump(int32_t fd, const std::vector<std::string> &args) ;
    int32_t NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle) ;
    bool CheckAndPackageAxisEvent(libinput_event* event) ;
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    bool CheckFilterMouseEvent(struct libinput_event *event) ;
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool NormalizeMoveMouse(int32_t offsetX, int32_t offsetY) ;
    void OnDisplayLost(int32_t displayId) ;
    int32_t GetDisplayId() const ;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t SetPointerLocation(int32_t x, int32_t y, int32_t displayId = -1) ;
    int32_t GetPointerLocation(int32_t &displayId, double &displayX, double &displayY) ;
    int32_t SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable) ;

    int32_t SetMouseScrollRows(int32_t rows) ;
    int32_t GetMouseScrollRows() const ;
    int32_t SetMousePrimaryButton(int32_t primaryButton) ;
    int32_t GetMousePrimaryButton() const ;
    int32_t SetPointerSpeed(int32_t speed) ;
    int32_t GetPointerSpeed() const ;
    int32_t GetTouchpadSpeed() const ;
    int32_t SetTouchpadScrollSwitch(int32_t pid, bool switchFlag) const ;
    void GetTouchpadScrollSwitch(bool &switchFlag) const ;
    int32_t SetTouchpadScrollDirection(bool state) const ;
    void GetTouchpadScrollDirection(bool &state) const ;
    int32_t SetTouchpadTapSwitch(bool switchFlag) const ;
    void GetTouchpadTapSwitch(bool &switchFlag) const ;
    int32_t SetTouchpadRightClickType(int32_t type) const ;
    void GetTouchpadRightClickType(int32_t &type) const ;
    int32_t SetTouchpadPointerSpeed(int32_t speed) const ;
    void GetTouchpadPointerSpeed(int32_t &speed) const ;
    void ReadTouchpadCDG(TouchpadCDG &touchpadCDG) const;

    // MouseDeviceState Interface
    int32_t GetMouseCoordsX() const;
    int32_t GetMouseCoordsY() const;
    void SetMouseCoords(int32_t x, int32_t y);
    bool IsLeftBtnPressed();
    void GetPressedButtons(std::vector<int32_t>& pressedButtons);
    void MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState);
    int32_t LibinputChangeToPointer(const uint32_t keyValue);

private:
    void SetUpDeviceObserver(std::shared_ptr<MouseEventInterface> self);
    void TearDownDeviceObserver();
    void OnDeviceAdded(std::shared_ptr<MouseEventInterface> self, int32_t deviceId);
    void OnDeviceRemoved(std::shared_ptr<MouseEventInterface> self, int32_t deviceId);
    void LoadMouse();
    void OnMouseLoaded();
    void UnloadMouse();

    mutable std::mutex mutex_;
    std::weak_ptr<IInputServiceContext> env_;
    std::shared_ptr<IDeviceObserver> inputDevObserver_;
    int32_t unloadTimerId_ { -1 };
    ComponentManager::Handle<IMouseEventNormalize> mouse_ {
        nullptr, ComponentManager::Component<IMouseEventNormalize>() };
};

#define MouseEventHdr OHOS::MMI::MouseEventInterface::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_EVENT_INTERFACE_H