/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#ifndef PROPERTY_READER_H
#define PROPERTY_READER_H

#include "delegate_interface.h"
#include "delegate_tasks.h"
#include "libinput.h"
#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class PropertyReader final {
    DECLARE_DELAYED_SINGLETON(PropertyReader);
public:
    DISALLOW_COPY_AND_MOVE(PropertyReader);
    void ReadPropertys(std::string path, DTaskCallback callback);
    void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy)
    {
        delegateProxy_ = proxy;
    }

private:
    std::shared_ptr<DelegateInterface> delegateProxy_ {nullptr};
};

#define PropReader ::OHOS::DelayedSingleton<PropertyReader>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // PROPERTY_READER_H