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

#include "infrared_emitter_controller.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InfraredEmitterController"

namespace OHOS {
namespace MMI {
using namespace OHOS::HDI::Consumerir::V1_0;
InfraredEmitterController *InfraredEmitterController::instance_ = new (std::nothrow) InfraredEmitterController();
InfraredEmitterController *InfraredEmitterController::GetInstance()
{
    return instance_;
}

void InfraredEmitterController::InitInfraredEmitter()
{
    CALL_DEBUG_ENTER;
    if (irInterface_ != nullptr) {
        MMI_HILOGE("infrared emitter has inited");
        return;
    }
    MMI_HILOGI("infrared emitter call ConsumerIr::Get()");
    irInterface_ = ConsumerIr::Get();
    if (irInterface_ == nullptr) {
        MMI_HILOGE("infrared emitter init error");
        return;
    }
    MMI_HILOGI("infrared emitter init ok");
}

bool InfraredEmitterController::Transmit(int64_t carrierFreq, std::vector<int64_t> pattern)
{
    CALL_DEBUG_ENTER;
    InitInfraredEmitter();
    if (!irInterface_) {
        MMI_HILOGE("infrared emitter not init");
        return false;
    }
    int32_t tempCarrierFreq = carrierFreq;
    std::vector<int32_t> tempPattern;
    std::string context = "infraredFrequency:" + std::to_string(tempCarrierFreq) + ";";
    for (size_t i = 0; i < pattern.size(); i++) {
        int32_t per = pattern[i];
        context = context + "index:" + std::to_string(i) + ": pattern:" + std::to_string(per) + ";";
        tempPattern.push_back(per);
    }
    MMI_HILOGI("irInterface_->Transmit params:%{public}s", context.c_str());
    bool outRet = false;
    int32_t ret = irInterface_->Transmit(tempCarrierFreq, tempPattern, outRet);
    MMI_HILOGI("irInterface_->Transmit ret:%{public}d", ret);
    if (ret < HDF_SUCCESS) {
        MMI_HILOGE("infrared emitter transmit %{public}d", ret);
        return false;
    }
    if (!outRet) {
        MMI_HILOGE("infrared emitter transmit out false");
        return false;
    }
    return true;
}

bool InfraredEmitterController::GetFrequencies(std::vector<InfraredFrequencyInfo> &frequencyInfo)
{
    CALL_DEBUG_ENTER;
    InitInfraredEmitter();
    if (!irInterface_) {
        MMI_HILOGE("infrared emitter not init");
        return false;
    }
    bool outRet = false;
    std::vector<ConsumerIrFreqRange> outRange;
    MMI_HILOGI("irInterface_->GetCarrierFreqs");
    int32_t ret = irInterface_->GetCarrierFreqs(outRet, outRange);
    MMI_HILOGI("irInterface_->GetCarrierFreqs ret:%{public}d", ret);
    if (ret < HDF_SUCCESS) {
        MMI_HILOGE("infrared emitter GetCarrierFreqs %{public}d", ret);
        return false;
    }
    if (!outRet) {
        MMI_HILOGE("infrared emitter GetCarrierFreqs out false");
        return false;
    }
    std::string context = "size:" + std::to_string(outRange.size()) + ";";
    for (size_t i = 0; i < outRange.size(); i++) {
        InfraredFrequencyInfo item;
        context = context + "index:" + std::to_string(i) + ": per.max:" + std::to_string(outRange[i].max) +
         ": per.min:" + std::to_string(outRange[i].min) + ";;";
        item.max_ = outRange[i].max;
        item.min_ = outRange[i].min;
        frequencyInfo.push_back(item);
    }
    MMI_HILOGI("data from hdf: %{public}s", context.c_str());
    return true;
}
} // namespace MMI
} // namespace OHOS

