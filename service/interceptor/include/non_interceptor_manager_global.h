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
#ifndef NON_INTERCEPTOR_MANAGER_GLOBAL_H
#define NON_INTERCEPTOR_MANAGER_GLOBAL_H

#include "i_interceptor_manager_global.h"

namespace OHOS {
namespace MMI {
class NonInterceptorManagerGlobal : public IInterceptorManagerGlobal {
public:
    NonInterceptorManagerGlobal();
    ~NonInterceptorManagerGlobal() = default;
    void OnAddInterceptor(int32_t sourceType, int32_t id, SessionPtr session);
    void OnRemoveInterceptor(int32_t id);
    bool OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    bool OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
};
} // namespace MMI
} // namespace OHOS
#endif // NON_INTERCEPTOR_MANAGER_GLOBAL_H