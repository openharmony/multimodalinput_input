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

#ifndef INTERCEPTOR_MANAGER_H
#define INTERCEPTOR_MANAGER_H

#include <list>

#include "nocopyable.h"
#include "singleton.h"

#include "i_input_event_consumer.h"

namespace OHOS {
namespace MMI {
class InterceptorManager : public DelayedSingleton<InterceptorManager> {
public:
    InterceptorManager();
    DISALLOW_COPY_AND_MOVE(InterceptorManager);
    ~InterceptorManager() = default;
    int32_t AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor);
    void RemoveInterceptor(int32_t interceptorId);
    int32_t OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent);

private:
    struct InterceptorItem {
        int32_t id_;
        bool operator == (struct InterceptorItem item) const
        {
            return id_ == item.id_;
        }
        int32_t sourceType;
        std::function<void(std::shared_ptr<PointerEvent>)> callback;
        std::function<void(std::shared_ptr<KeyEvent>)> callback_;
    };
private:
    int32_t InterceptorItemId = 0;
    std::list<InterceptorItem> interceptor_;
};
} // namespace MMI
} // namespace OHOS
#endif // INTERCEPTOR_MANAGER_H