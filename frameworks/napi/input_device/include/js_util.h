/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef JS_UTIL_H
#define JS_UTIL_H

#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "refbase.h"

#include "input_device.h"

namespace OHOS {
namespace MMI {
class JsUtil {
public:
    struct UserData {
        int32_t userData { 0 };
        int32_t deviceId { 0 };
        napi_value handle { nullptr };
        std::vector<int32_t> keys;
    };
    struct CallbackData {
        std::vector<int32_t> ids;
        std::shared_ptr<InputDevice> device { nullptr };
        std::vector<bool> keystrokeAbility;
        int32_t deviceId { 0 };
        int32_t keyboardType { 0 };
        int32_t keyboardRepeatDelay { 0 };
        int32_t keyboardRepeatRate { 0 };
    };
    struct ReportData : RefBase {
        napi_ref ref { nullptr };
        int32_t deviceId { 0 };
    };
    struct CallbackInfo : RefBase {
        napi_env env { nullptr };
        napi_ref ref { nullptr };
        napi_deferred deferred { nullptr };
        int32_t errCode { -1 };
        CallbackData data;
        UserData uData;
        bool isApi9 { false };
    };
    struct DeviceType {
        std::string sourceTypeName;
        uint32_t typeBit { 0 };
    };

    static bool IsSameHandle(napi_env env, napi_value handle, napi_ref ref);
    static napi_value GetDeviceInfo(sptr<CallbackInfo> cb);
    static bool GetDeviceAxisInfo(sptr<CallbackInfo> cb, napi_value &object);
    static bool GetDeviceSourceType(sptr<CallbackInfo> cb, napi_value &object);
    static bool TypeOf(napi_env env, napi_value value, napi_valuetype type);
    static void DeleteCallbackInfo(std::unique_ptr<CallbackInfo> callback);
    template <typename T>
    static void DeletePtr(T &ptr)
    {
        if (ptr != nullptr) {
            delete ptr;
            ptr = nullptr;
        }
    }
};
} // namespace MMI
} // namespace OHOS
#endif // JS_UTIL_H