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
#ifndef I_INTERCEPTOR_MANAGER_GLOBAL_H
#define I_INTERCEPTOR_MANAGER_GLOBAL_H

#include "nocopyable.h"
#include "singleton.h"

#include "key_event.h"
#include "pointer_event.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class IInterceptorManagerGlobal : public DelayedSingleton<IInterceptorManagerGlobal> {
public:
    IInterceptorManagerGlobal() = default;
    ~IInterceptorManagerGlobal() = default;
    DISALLOW_COPY_AND_MOVE(IInterceptorManagerGlobal);
    void OnAddInterceptor(int32_t sourceType, int32_t id, SessionPtr session);
    void OnRemoveInterceptor(int32_t id);
    bool OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
};
} // namespace MMI
} // namespace OHOS
#endif // I_INTERCEPTOR_MANAGER_GLOBAL_H