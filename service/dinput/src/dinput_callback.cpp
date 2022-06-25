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

#include "dinput_callback.h"

#include "define_multimodal.h"

#include "dinput_manager.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDinputService" };
}

void PrepareDInputCallback::OnResult(const std::string& deviceId, const int32_t& status)
{
    MMI_HILOGI("PrepareDInputCallback OnResult deviceId:%{public}s, status:%{public}d",
        GetAnonyString(deviceId).c_str(), status);
    CHKPV(callback_);
    callback_->HandlePrepareDinput(deviceId, status);
}

void StartDInputCallback::OnResult(const std::string& deviceId, const uint32_t& inputTypes, const int32_t& status)
{
    MMI_HILOGI("StartDInputCallback OnResult deviceId:%{public}s, status:%{public}d",
        GetAnonyString(deviceId).c_str(), status);
    CHKPV(callback_);
    callback_->HandleStartDinput(deviceId, inputTypes, status);
    if (status != 0) {
        MMI_HILOGI("StartDInputCallback OnResult status:%{public}d", status);
    }
    DInputMgr->OnStartRemoteInput(deviceId, inputTypes);
}

void StopDInputCallback::OnResult(const std::string& deviceId, const uint32_t& inputTypes, const int32_t& status)
{
    MMI_HILOGI("StopDInputCallback OnResult:%{public}s, status:%{public}d", GetAnonyString(deviceId).c_str(), status);
    CHKPV(callback_);
    callback_->HandleStopDinput(deviceId, inputTypes, status);
    if (status != 0) {
        MMI_HILOGI("StopDInputCallback OnResult status:%{public}d", status);
    }
    DInputMgr->OnStopRemoteInput(deviceId, inputTypes);
}

void UnprepareDInputCallback::OnResult(const std::string& deviceId, const int32_t& status)
{
    MMI_HILOGI("UnprepareDInputCallback OnResult:%{public}s, status:%{public}d",
        GetAnonyString(deviceId).c_str(), status);
    CHKPV(callback_);
    callback_->HandleUnprepareDinput(deviceId, status);
}
} // namespace MMI
} // namespace OHOS
