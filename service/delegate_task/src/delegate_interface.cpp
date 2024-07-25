/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "delegate_interface.h"

#include "error_multimodal.h"
#include "mmi_log.h"
#include "touch_drawing_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DelegateInterface"

namespace OHOS {
namespace MMI {

void DelegateInterface::Init()
{
    TOUCH_DRAWING_MGR->SetDelegateProxy(shared_from_this());
}

int32_t DelegateInterface::OnPostSyncTask(DTaskCallback cb) const
{
    CHKPR(delegateTasks_, ERROR_NULL_POINTER);
    int32_t ret = delegateTasks_(cb);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to execute the task, ret: %{public}d", ret);
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS