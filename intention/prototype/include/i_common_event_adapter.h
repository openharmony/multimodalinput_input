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

#ifndef I_COMMON_EVENT_ADAPTER_H
#define I_COMMON_EVENT_ADAPTER_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using CommonEventHandleType = std::function<void(const std::string &event)>;

class ICommonEventObserver : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ICommonEventObserver(const OHOS::EventFwk::CommonEventSubscribeInfo &info)
        : CommonEventSubscriber(info) {}
    virtual ~ICommonEventObserver() = default;

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &event) override = 0;
};

class ICommonEventAdapter {
public:
    ICommonEventAdapter() = default;
    virtual ~ICommonEventAdapter() = default;

    virtual int32_t AddObserver(std::shared_ptr<ICommonEventObserver> observer) = 0;
    virtual int32_t RemoveObserver(std::shared_ptr<ICommonEventObserver> observer) = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_COMMON_EVENT_ADAPTER_H
