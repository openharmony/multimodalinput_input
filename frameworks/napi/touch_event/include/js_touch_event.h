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

#ifndef JS_TOUCH_EVENT
#define JS_TOUCH_EVENT

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class JsTouchEvent {
public:
    JsTouchEvent() = default;
    ~JsTouchEvent() = default;
    DISALLOW_COPY_AND_MOVE(JsTouchEvent);
    static napi_value Export(napi_env env, napi_value exports);
private:
    static napi_value GetNapiInt32(napi_env env, int32_t code);
    static napi_value EnumClassConstructor(napi_env env, napi_callback_info info);
};
} // namespace MMI
} // namespace OHOS

#endif // JS_TOUCH_EVENT