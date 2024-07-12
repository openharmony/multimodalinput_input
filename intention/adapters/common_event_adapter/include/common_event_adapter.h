/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_EVENT_ADAPTER_H
#define COMMON_EVENT_ADAPTER_H

#include "nocopyable.h"

#include "common_event_observer.h"

#include "i_common_event_adapter.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CommonEventAdapter : public ICommonEventAdapter {
public:
    CommonEventAdapter() = default;
    ~CommonEventAdapter() = default;
    DISALLOW_COPY_AND_MOVE(CommonEventAdapter);

    int32_t AddObserver(std::shared_ptr<ICommonEventObserver> observer) override;
    int32_t RemoveObserver(std::shared_ptr<ICommonEventObserver> observer) override;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COMMON_EVENT_ADAPTER_H
