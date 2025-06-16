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

#include "input_binder_client_server_impl.h"
#include "mmi_log.h"
#include "input_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputBinderClientServerImpl"

namespace OHOS {
namespace MMI {
ErrCode InputBinderClientServerImpl::NoticeRequestInjectionResult(int32_t reqId, int32_t status)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->RequestInjectionCallback(reqId, status);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS