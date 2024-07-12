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

#ifndef COMMON_EVENT_OBSERVER_H
#define COMMON_EVENT_OBSERVER_H

#include <memory>

#include "nocopyable.h"

#include "i_common_event_adapter.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CommonEventObserver : public ICommonEventObserver {
public:
    CommonEventObserver(const OHOS::EventFwk::CommonEventSubscribeInfo &info, CommonEventHandleType handle)
        : ICommonEventObserver(info), handle_(handle) {}
    ~CommonEventObserver() = default;

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &event) override;
    static std::shared_ptr<CommonEventObserver> CreateCommonEventObserver(CommonEventHandleType handle);
private:
    CommonEventHandleType handle_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COMMON_EVENT_OBSERVER_H
