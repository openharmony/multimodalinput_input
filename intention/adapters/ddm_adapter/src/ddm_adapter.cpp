/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ddm_adapter.h"

#include "ddm_adapter_impl.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "DDMAdapter"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

DDMAdapter::DDMAdapter()
{
    ddm_ = std::make_shared<DDMAdapterImpl>();
}

int32_t DDMAdapter::Enable()
{
    CALL_DEBUG_ENTER;
    return ddm_->Enable();
}

void DDMAdapter::Disable()
{
    CALL_DEBUG_ENTER;
    ddm_->Disable();
}

void DDMAdapter::AddBoardObserver(std::shared_ptr<IBoardObserver> observer)
{
    CALL_DEBUG_ENTER;
    ddm_->AddBoardObserver(observer);
}

void DDMAdapter::RemoveBoardObserver(std::shared_ptr<IBoardObserver> observer)
{
    CALL_DEBUG_ENTER;
    ddm_->RemoveBoardObserver(observer);
}

bool DDMAdapter::CheckSameAccountToLocal(const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    return ddm_->CheckSameAccountToLocal(networkId);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
