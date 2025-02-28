/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JS_GESTURE_EVENT
#define JS_GESTURE_EVENT
#include "napi/native_node_api.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class JsGestureEvent final {
public:
    enum class TouchGesturAction : int32_t {
        SWIPE_DOWN = 0,
        SWIPE_UP,
        SWIPE_LEFT,
        SWIPE_RIGHT,
        PINCH_CLOSED,
        PINCH_OPENED,
        GESTURE_END
    };
    JsGestureEvent() = default;
    ~JsGestureEvent() = default;
    DISALLOW_COPY_AND_MOVE(JsGestureEvent);
    static napi_value Export(napi_env env, napi_value exports);
private:
    static napi_value GetNapiString(napi_env env, std::string str);
    static napi_value GetNapiInt32(napi_env env, int32_t code);
    static napi_value EnumClassConstructor(napi_env env, napi_callback_info info);
};
} // namespace MMI
} // namespace OHOS
#endif // JS_GESTURE_EVENT