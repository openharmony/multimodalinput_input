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

#include <dlfcn.h>

#include "infrared_emitter_controller.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InfraredEmitterController"

namespace OHOS {
namespace MMI {
namespace {
    const std::string IR_WRAPPER_PATH = "libconsumer_ir_service_1.0.z.so";
}
using namespace OHOS::HDI::Consumerir::V1_0;
InfraredEmitterController *InfraredEmitterController::instance_ = new (std::nothrow) InfraredEmitterController();
InfraredEmitterController::InfraredEmitterController() {}

InfraredEmitterController::~InfraredEmitterController()
{
    CALL_DEBUG_ENTER;
    CHKPV(irInterface_);
    MMI_HILOGD("start release irInterface_");
    irInterface_ = nullptr;
    CHKPV(soIrHandle);
    MMI_HILOGD("start release so handler");
    dlclose(soIrHandle);
    soIrHandle = nullptr;
    MMI_HILOGD("end release");
}

InfraredEmitterController *InfraredEmitterController::GetInstance()
{
    return instance_;
}

void InfraredEmitterController::InitInfraredEmitter()
{
    CALL_DEBUG_ENTER;
    if (!irInterface_) {
        MMI_HILOGE("infrared emitter inited");
        return;
    }
    if (!soIrHandle) {
        MMI_HILOGD("begin load so %{public}s", IR_WRAPPER_PATH.c_str());
        soIrHandle = dlopen(IR_WRAPPER_PATH.c_str(), RTLD_NOW);
        if (nullptr == soIrHandle) {
            MMI_HILOGE("so %{public}s was not loaded, error: %{public}s", IR_WRAPPER_PATH.c_str(), dlerror());
            return;
        }
    }
    typedef ConsumerIr* (*funCreate_ptr) (void);
    funCreate_ptr fnCreate = nullptr;
    fnCreate = (funCreate_ptr)dlsym(soIrHandle, "ConsumerIrImplGetInstance");
    const char *dlsymError = dlerror();
    if (dlsymError) {
        MMI_HILOGE("load ConsumerIrImplGetInstance, error: %{public}s", dlsymError);
        dlclose(soIrHandle);
        soIrHandle = nullptr;
        return;
    }
    if (!fnCreate) {
        MMI_HILOGE("loaded ConsumerIrImplGetInstance is null");
        dlclose(soIrHandle);
        soIrHandle = nullptr;
        return;
    }
    MMI_HILOGI("infrared emitter call ConsumerIr:fnCreate begin");
    irInterface_ = (ConsumerIr *)fnCreate();
    if (nullptr == irInterface_) {
        MMI_HILOGE("infrared emitter init fail irInterface_ is nullptr");
        dlclose(soIrHandle);
        soIrHandle = nullptr;
        return;
    }
    MMI_HILOGI("infrared emitter init sucess.");
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
    if (ret < 0) {
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
    if (ret < 0) {
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
        context = context + "index:" + std::to_string(i) + ": per.max:" + std::to_string(outRange[i].max_) +
                  ": per.min:" + std::to_string(outRange[i].min_) + ";;";
        item.max_ = outRange[i].max_;
        item.min_ = outRange[i].min_;
        frequencyInfo.push_back(item);
    }
    MMI_HILOGI("data from hdf: %{public}s", context.c_str());
    return true;
}
} // namespace MMI
} // namespace OHOS

