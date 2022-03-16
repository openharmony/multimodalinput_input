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

#ifndef JS_EVENT_TARGET_H
#define JS_EVENT_TARGET_H
#include <map>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/log.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_device_impl.h"
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
class JsEventTarget {
public:
    JsEventTarget() = default;
    DISALLOW_COPY_AND_MOVE(JsEventTarget);

    static void EmitJsIdsAsync(int32_t userData, std::vector<int32_t> ids);
    static void CallIdsAsyncWork(napi_env env, napi_status status, void* data);

    static void EmitJsIdsPromise(int32_t userData, std::vector<int32_t> ids);
    static void CallIdsPromiseWork(napi_env env, napi_status status, void* data);

    static void EmitJsDevAsync(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device);
    static void CallDevAsyncWork(napi_env env, napi_status status, void* data);

    static void EmitJsDevPromise(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device);
    static void CallDevPromiseWork(napi_env env, napi_status status, void* data);

    napi_value CreateCallbackInfo(napi_env env, napi_value handle);
    void ResetEnv();
    static bool CheckEnv(napi_env env);

    struct CallbackInfo {
        napi_ref ref = nullptr;
        napi_async_work asyncWork = nullptr;
        napi_deferred deferred = nullptr;
        napi_value promise = nullptr;
        std::vector<int32_t> ids = {0};
        std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device = nullptr;
    };
    struct DeviceType {
        std::string deviceTypeName;
        uint32_t typeBit;
    };

    static constexpr uint32_t EVDEV_UDEV_TAG_KEYBOARD = (1 << 1);
    static constexpr uint32_t EVDEV_UDEV_TAG_MOUSE = (1 << 2);
    static constexpr uint32_t EVDEV_UDEV_TAG_TOUCHPAD = (1 << 3);
    static constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
    static constexpr uint32_t EVDEV_UDEV_TAG_TABLET = (1 << 5);
    static constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
    static constexpr uint32_t EVDEV_UDEV_TAG_ACCELEROMETER = (1 << 7);
    static constexpr uint32_t EVDEV_UDEV_TAG_TABLET_PAD = (1 << 8);
    static constexpr uint32_t EVDEV_UDEV_TAG_POINTINGSTICK = (1 << 9);
    static constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);
    static constexpr uint32_t EVDEV_UDEV_TAG_SWITCH = (1 << 11);

    static napi_env env_;
    static int32_t userData_;
};
} // namespace MMI
} // namespace OHOS

#endif // JS_EVENT_TARGET_H