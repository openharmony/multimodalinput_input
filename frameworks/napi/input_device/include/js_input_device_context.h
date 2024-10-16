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

#ifndef JS_INPUT_DEVICE_CONTEXT_H
#define JS_INPUT_DEVICE_CONTEXT_H

#include "js_input_device_manager.h"

namespace OHOS {
namespace MMI {
class JsInputDeviceContext final {
public:
    JsInputDeviceContext();
    DISALLOW_COPY_AND_MOVE(JsInputDeviceContext);
    ~JsInputDeviceContext();
    static napi_value Export(napi_env env, napi_value exports);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value GetDeviceIds(napi_env env, napi_callback_info info);
    static napi_value GetDevice(napi_env env, napi_callback_info info);
    static napi_value GetDeviceList(napi_env env, napi_callback_info info);
    static napi_value GetDeviceInfo(napi_env env, napi_callback_info info);
    static napi_value GetDeviceInfoSync(napi_env env, napi_callback_info info);
    static napi_value SupportKeys(napi_env env, napi_callback_info info);
    static napi_value SupportKeysSync(napi_env env, napi_callback_info info);
    static napi_value GetKeyboardType(napi_env env, napi_callback_info info);
    static napi_value GetKeyboardTypeSync(napi_env env, napi_callback_info info);
    static napi_value SetKeyboardRepeatDelay(napi_env env, napi_callback_info info);
    static napi_value SetKeyboardRepeatRate(napi_env env, napi_callback_info info);
    static napi_value GetKeyboardRepeatDelay(napi_env env, napi_callback_info info);
    static napi_value GetKeyboardRepeatRate(napi_env env, napi_callback_info info);
    static napi_value GetIntervalSinceLastInput(napi_env env, napi_callback_info info);
    std::shared_ptr<JsInputDeviceManager> GetJsInputDeviceMgr() const;
    static napi_value SetVKeyboardArea(napi_env env, napi_callback_info info);
    static napi_value UpdateMotionSpace(napi_env env, napi_callback_info info);

public:
    enum class MotionSpaceType : int32_t {
        NARROW = 0,
        WIDE = 1,
        FLOATING = 2,
        TRACKPAD = 3,
        OTHERS = 10,
    };
    enum class PageType : int32_t {
        FIRST_PAGE = 0,
        SECOND_PAGE_CN = 1,
        SECOND_PAGE_EN = 2,
        OTHERS = 10,
    };
    struct ButtonMotionSpace {
        std::string keyName;
        int32_t keyCode;
        double locX;
        double locY;
        double width;
        double height;
        bool useShift;
        MotionSpaceType motionSpaceTypeId;
        PageType pageTypeId;
    };

private:
    static napi_value CreateInstance(napi_env env);
    static JsInputDeviceContext* GetInstance(napi_env env);
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
#ifdef OHOS_BUILD_ENABLE_HOPPER
    static bool ParseBMSArray(const napi_env& env, const napi_value& value,
        std::vector<ButtonMotionSpace*>& bmsArray);
#endif // OHOS_BUILD_ENABLE_HOPPER
    static napi_value EnumClassConstructor(napi_env env, napi_callback_info info);
    static napi_value CreateEnumKeyboardType(napi_env env, napi_value exports);
    static napi_value CreateEnumVKResult(napi_env env, napi_value exports);
    static napi_value CreateEnumMotionSpaceType(napi_env env, napi_value exports);
    static napi_value CreateEnumPageType(napi_env env, napi_value exports);
    std::shared_ptr<JsInputDeviceManager> mgr_ { nullptr };
    napi_ref contextRef_ { nullptr };
    std::mutex mtx_;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_DEVICE_CONTEXT_H