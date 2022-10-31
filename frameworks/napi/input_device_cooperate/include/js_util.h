/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef JS_UTIL_H
#define JS_UTIL_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <napi/native_api.h>

#include "cooperation_message.h"

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
        bool enableResult { false };
        bool startResult { false };
        bool stopResult { false };
        bool cooperateOpened { false };
        std::string deviceDescriptor;
        int32_t errCode { 0 };
        CooperationMessage msg = CooperationMessage::OPEN_SUCCESS;
    };

    struct CallbackInfo {
        CallbackInfo() = default;
        ~CallbackInfo();
        napi_env env { nullptr };
        napi_ref ref { nullptr };
        napi_deferred deferred { nullptr };
        int32_t errCode { 0 };
        CallbackData data;
        UserData uData;
    };

    static napi_value GetEnableInfo(const std::unique_ptr<CallbackInfo> &cb);
    static napi_value GetStartInfo(const std::unique_ptr<CallbackInfo> &cb);
    static napi_value GetStopInfo(const std::unique_ptr<CallbackInfo> &cb);
    static napi_value GetStateInfo(const std::unique_ptr<CallbackInfo> &cb);
    static napi_value GetStateResult(napi_env env, bool result);
    static napi_value GetResult(napi_env env, bool result, int32_t errCode);
    static bool IsSameHandle(napi_env env, napi_value handle, napi_ref ref);

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
