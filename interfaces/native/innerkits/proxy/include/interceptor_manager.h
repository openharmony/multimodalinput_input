/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "pointer_event.h"
#include "singleton.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
class InterceptorManager {
public:
    InterceptorManager();
    ~InterceptorManager();
    int32_t AddInterceptor(int32_t sourceType, std::function<void(std::shared_ptr<PointerEvent>)> interceptor);
    void RemoveInterceptor(int32_t interceptorId);
    int32_t OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
private:
    struct InterceptorItem {
        int32_t id_;
        bool operator == (struct InterceptorItem item) const
        {
            return this->id_ == item.id_;
        }
        int32_t sourceType;
        std::function<void(std::shared_ptr<PointerEvent>)> callback;
    };
private:
    int32_t InterceptorItemId;
    std::list<InterceptorItem> interceptor_;
};
}
}

#define INTERCEPTORMANAGER OHOS::Singleton<OHOS::MMI::InterceptorManager>::GetInstance()
#endif