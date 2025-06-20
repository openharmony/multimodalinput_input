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

#include <dlfcn.h>
#include "idevmgr_hdi.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InfraredEmitterController"

namespace OHOS {
namespace MMI {
namespace {
const std::string CONSUMER_NAME = "consumerir_service";
std::mutex mutex_;
}

InfraredEmitterController *InfraredEmitterController::instance_ = new (std::nothrow) InfraredEmitterController();
InfraredEmitterController::InfraredEmitterController() {}

InfraredEmitterController::~InfraredEmitterController() {}

InfraredEmitterController *InfraredEmitterController::GetInstance()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return instance_;
}

sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> InfraredEmitterController::InitInfraredEmitter()
{
    MMI_HILOGI("Infrared emitter call ConsumerIr:fnCreate begin");
    sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> consumerIr =
        OHOS::HDI::Consumerir::V1_0::ConsumerIr::Get(CONSUMER_NAME);
    if (consumerIr != nullptr) {
        return consumerIr;
    }
    auto devmgr = OHOS::HDI::DeviceManager::V1_0::IDeviceManager::Get();
    if (devmgr == nullptr) {
        MMI_HILOGE("devmgr is null.");
        return nullptr;
    }
    if (devmgr->LoadDevice(CONSUMER_NAME) != 0) {
        MMI_HILOGE("LoadDevice(%{public}s) failed.", CONSUMER_NAME.c_str());
        return nullptr;
    }
    consumerIr = OHOS::HDI::Consumerir::V1_0::ConsumerIr::Get(CONSUMER_NAME);
    if (consumerIr == nullptr) {
        MMI_HILOGE("Infrared emitter init fail consumerIr is nullptr");
        return nullptr;
    }
    return consumerIr;
}

bool InfraredEmitterController::Transmit(int64_t carrierFreq, const std::vector<int64_t> pattern)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> consumerIr = InitInfraredEmitter();
    CHKPF(consumerIr);
    int32_t tempCarrierFreq = carrierFreq;
    std::vector<int32_t> tempPattern;
    std::string context = "infraredFrequency:" + std::to_string(tempCarrierFreq) + ";";
    for (size_t i = 0; i < pattern.size(); i++) {
        int32_t per = pattern[i];
        context = context + "index:" + std::to_string(i) + ": pattern:" + std::to_string(per) + ";";
        tempPattern.push_back(per);
    }
    MMI_HILOGI("consumerIr->Transmit params:%{public}s", context.c_str());

    bool outRet = false;
    int32_t ret = consumerIr->Transmit(tempCarrierFreq, tempPattern, outRet);
    MMI_HILOGI("consumerIr->Transmit ret:%{public}d", ret);
    if (ret < 0) {
        MMI_HILOGE("Infrared emitter transmit failed:%{public}d", ret);
        return false;
    }
    if (!outRet) {
        MMI_HILOGE("Infrared emitter transmit out false");
        return false;
    }
    return true;
}

bool InfraredEmitterController::GetFrequencies(std::vector<InfraredFrequencyInfo> &frequencyInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> consumerIr = InitInfraredEmitter();
    CHKPF(consumerIr);
    bool outRet = false;
    std::vector<OHOS::HDI::Consumerir::V1_0::ConsumerIrFreqRange> outRange;
    MMI_HILOGI("consumerIr->GetCarrierFreqs");
    int32_t ret = consumerIr->GetCarrierFreqs(outRet, outRange);
    MMI_HILOGI("consumerIr->GetCarrierFreqs ret:%{public}d", ret);
    if (ret < 0) {
        MMI_HILOGE("Infrared emitter GetCarrierFreqs failed:%{public}d", ret);
        return false;
    }
    if (!outRet) {
        MMI_HILOGE("Infrared emitter GetCarrierFreqs out false");
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
    MMI_HILOGD("consumerIr->GetCarrierFreqs context:%{public}s", context.c_str());
    return true;
}
} // namespace MMI
} // namespace OHOS

