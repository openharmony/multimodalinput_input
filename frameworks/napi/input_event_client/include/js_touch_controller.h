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

#ifndef JS_TOUCH_CONTROLLER_H
#define JS_TOUCH_CONTROLLER_H

#include <memory>

#include "touch_controller_impl.h"

namespace OHOS {
namespace MMI {

class JsTouchController {
public:
    explicit JsTouchController(std::shared_ptr<TouchControllerImpl> impl);
    ~JsTouchController() = default;

    int32_t TouchDown(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY);
    int32_t TouchMove(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY);
    int32_t TouchUp(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY);

private:
    std::shared_ptr<TouchControllerImpl> impl_;
};

} // namespace MMI
} // namespace OHOS

#endif // JS_TOUCH_CONTROLLER_H
