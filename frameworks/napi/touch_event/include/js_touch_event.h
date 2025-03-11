/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef JS_TOUCH_EVENT
#define JS_TOUCH_EVENT

#include "napi/native_node_api.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class JsTouchEvent final {
public:
    enum class Action : int32_t {
        CANCEL = 0,
        DOWN = 1,
        MOVE = 2,
        UP = 3,
        PULL_DOWN = 4,
        PULL_MOVE = 5,
        PULL_UP = 6,
    };

    enum class ToolType : int32_t {
        FINGER = 0,
        PEN = 1,
        RUBBER = 2,
        BRUSH = 3,
        PENCIL = 4,
        AIRBRUSH = 5,
        MOUSE = 6,
        LENS = 7,
    };

    enum class SourceType : int32_t {
        TOUCH_SCREEN = 0,
        PEN = 1,
        TOUCH_PAD = 2,
    };

    enum class FixedMode : int32_t {
        NONE = 0,
        ONE_HAND = 1,
    };
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