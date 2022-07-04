/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "anr_callback.h"

#include "mmi_log.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "AnrCallback" };
} // namespace

void AnrCallback::SetAnrCallback(std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    callback_ = callback;
    int32_t ret = MultimodalInputConnMgr->SetAnrCallback();
    if (ret != RET_OK) {
        MMI_HILOGE("send to server fail, ret:%{public}d", ret);
    }
}

void AnrCallback::OnAnrNoticed(int32_t pid)
{
    CALL_DEBUG_ENTER;
    CHKPV(callback_);
    callback_(pid);
}
} // namespace MMI
} // namespace OHOS
