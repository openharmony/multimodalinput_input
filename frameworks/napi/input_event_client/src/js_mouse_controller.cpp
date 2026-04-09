/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_mouse_controller.h"

#include "define_multimodal.h"
#include "input_manager.h"
#include "js_register_module.h"
#include "mmi_log.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsMouseController"

namespace OHOS {
namespace MMI {

namespace {
// Button mapping: JS enum -> PointerEvent constant
// Use JS_MOUSE_BUTTON_* constants from js_register_module.h
const std::map<int32_t, int32_t> JS_BUTTON_TO_NATIVE = {
    { JS_MOUSE_BUTTON_LEFT, PointerEvent::MOUSE_BUTTON_LEFT },
    { JS_MOUSE_BUTTON_MIDDLE, PointerEvent::MOUSE_BUTTON_MIDDLE },
    { JS_MOUSE_BUTTON_RIGHT, PointerEvent::MOUSE_BUTTON_RIGHT },
    { JS_MOUSE_BUTTON_SIDE, PointerEvent::MOUSE_BUTTON_SIDE },
    { JS_MOUSE_BUTTON_EXTRA, PointerEvent::MOUSE_BUTTON_EXTRA },
    { JS_MOUSE_BUTTON_FORWARD, PointerEvent::MOUSE_BUTTON_FORWARD },
    { JS_MOUSE_BUTTON_BACK, PointerEvent::MOUSE_BUTTON_BACK },
    { JS_MOUSE_BUTTON_TASK, PointerEvent::MOUSE_BUTTON_TASK }
};

// Axis mapping: JS enum -> PointerEvent AxisType
// Use JS_MOUSE_AXIS_* constants from js_register_module.h
const std::map<int32_t, PointerEvent::AxisType> JS_AXIS_TO_NATIVE = {
    { JS_MOUSE_AXIS_SCROLL_VERTICAL, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL },
    { JS_MOUSE_AXIS_SCROLL_HORIZONTAL, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL },
    { JS_MOUSE_AXIS_PINCH, PointerEvent::AXIS_TYPE_PINCH }
};
} // namespace

JsMouseController::JsMouseController()
{
    MMI_HILOGD("Creating JsMouseController");
    // Create the core implementation instance via InputManager
    impl_ = InputManager::GetInstance()->CreateMouseController();
    if (impl_ == nullptr) {
        MMI_HILOGE("Failed to create MouseControllerImpl");
    }
}

int32_t JsMouseController::ConvertJsButtonToNative(int32_t jsButton)
{
    auto it = JS_BUTTON_TO_NATIVE.find(jsButton);
    if (it != JS_BUTTON_TO_NATIVE.end()) {
        return it->second;
    }
    MMI_HILOGW("Unknown JS button: %{public}d, using as-is", jsButton);
    return jsButton;
}

int32_t JsMouseController::ConvertJsAxisToNative(int32_t jsAxis)
{
    auto it = JS_AXIS_TO_NATIVE.find(jsAxis);
    if (it != JS_AXIS_TO_NATIVE.end()) {
        return static_cast<int32_t>(it->second);
    }
    MMI_HILOGW("Unknown JS axis: %{public}d, using as-is", jsAxis);
    return jsAxis;
}

int32_t JsMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("MouseControllerImpl is null");
        return RET_ERR;
    }
    return impl_->MoveTo(displayId, x, y);
}

int32_t JsMouseController::PressButton(int32_t button)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("MouseControllerImpl is null");
        return RET_ERR;
    }
    int32_t nativeButton = ConvertJsButtonToNative(button);
    return impl_->PressButton(nativeButton);
}

int32_t JsMouseController::ReleaseButton(int32_t button)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("MouseControllerImpl is null");
        return RET_ERR;
    }
    int32_t nativeButton = ConvertJsButtonToNative(button);
    return impl_->ReleaseButton(nativeButton);
}

int32_t JsMouseController::BeginAxis(int32_t axis, int32_t value)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("MouseControllerImpl is null");
        return RET_ERR;
    }
    int32_t nativeAxis = ConvertJsAxisToNative(axis);
    return impl_->BeginAxis(nativeAxis, value);
}

int32_t JsMouseController::UpdateAxis(int32_t axis, int32_t value)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("MouseControllerImpl is null");
        return RET_ERR;
    }
    int32_t nativeAxis = ConvertJsAxisToNative(axis);
    return impl_->UpdateAxis(nativeAxis, value);
}

int32_t JsMouseController::EndAxis(int32_t axis)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("MouseControllerImpl is null");
        return RET_ERR;
    }
    int32_t nativeAxis = ConvertJsAxisToNative(axis);
    return impl_->EndAxis(nativeAxis);
}

} // namespace MMI
} // namespace OHOS
