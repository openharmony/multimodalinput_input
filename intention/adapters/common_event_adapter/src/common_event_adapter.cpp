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

#include "common_event_adapter.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "CommonEventAdapter"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
int32_t CommonEventAdapter::AddObserver(std::shared_ptr<ICommonEventObserver> observer)
{
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(observer)) {
        FI_HILOGE("SubscribeCommonEvent failed");
        return RET_ERR;
    }
    FI_HILOGI("SubscribeCommonEvent success");
    return RET_OK;
}

int32_t CommonEventAdapter::RemoveObserver(std::shared_ptr<ICommonEventObserver> observer)
{
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(observer)) {
        FI_HILOGE("UnSubscribeCommonEvent failed");
        return RET_ERR;
    }
    FI_HILOGI("UnSubscribeCommonEvent success");
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
