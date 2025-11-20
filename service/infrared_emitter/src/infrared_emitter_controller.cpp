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

#include "error_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InfraredEmitterController"

namespace OHOS {
namespace MMI {
namespace {
const char* INFRARED_ADAPTER_PATH = "libinfrared_emitter_adapter.z.so";
std::mutex mutex_;
}
using namespace OHOS::HDI::Consumerir::V1_0;
InfraredEmitterController *InfraredEmitterController::instance_ = new (std::nothrow) InfraredEmitterController();
InfraredEmitterController::InfraredEmitterController() {}

InfraredEmitterController::~InfraredEmitterController()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (soIrHandle_ != nullptr) {
        typedef void (*funDestroyPtr) (IInfraredEmitterAdapter*);
        funDestroyPtr fnDestroy = (funDestroyPtr)dlsym(soIrHandle_, "DestroyInstance");
        if (fnDestroy != nullptr) {
            fnDestroy(irInterface_);
            irInterface_ = nullptr;
        }
        dlclose(soIrHandle_);
        soIrHandle_ = nullptr;
    }
}

InfraredEmitterController *InfraredEmitterController::GetInstance()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return instance_;
}

void InfraredEmitterController::InitInfraredEmitter()
{
    CALL_DEBUG_ENTER;
    if (irInterface_ != nullptr) {
        return;
    }
    if (soIrHandle_ == nullptr) {
        soIrHandle_ = dlopen(INFRARED_ADAPTER_PATH, RTLD_NOW);
        if (soIrHandle_ == nullptr) {
            MMI_HILOGE("Loaded %{private}s failed:%{public}s", INFRARED_ADAPTER_PATH, dlerror());
            return;
        }
    }
    typedef IInfraredEmitterAdapter* (*funCreatePtr) (void);
    funCreatePtr fnCreate = nullptr;
    fnCreate = (funCreatePtr)dlsym(soIrHandle_, "ConsumerIrImplGetInstance");
    const char *dlsymError = dlerror();
    if (dlsymError != nullptr) {
        MMI_HILOGE("Loaded ConsumerIrImplGetInstance failed:%{public}s", dlsymError);
        dlclose(soIrHandle_);
        soIrHandle_ = nullptr;
        return;
    }
    if (fnCreate == nullptr) {
        MMI_HILOGE("Loaded ConsumerIrImplGetInstance is null");
        dlclose(soIrHandle_);
        soIrHandle_ = nullptr;
        return;
    }
    MMI_HILOGI("Infrared emitter call IInfraredEmitterAdapter:fnCreate begin");
    irInterface_ = (IInfraredEmitterAdapter *)fnCreate();
    if (irInterface_ == nullptr) {
        MMI_HILOGE("Infrared emitter init fail irInterface_ is nullptr");
        dlclose(soIrHandle_);
        soIrHandle_ = nullptr;
        return;
    }
}

bool InfraredEmitterController::Transmit(int64_t carrierFreq, const std::vector<int64_t> pattern)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    InitInfraredEmitter();
    CHKPF(irInterface_);
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
        MMI_HILOGE("Infrared emitter transmit failed:%{public}d", ret);
        return false;
    }
    if (!outRet) {
        MMI_HILOGE("Infrared emitter transmit out false");
        return false;
    }
    return true;
}

int32_t InfraredEmitterController::GetFrequencies(std::vector<InfraredFrequencyInfo> &frequencyInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    InitInfraredEmitter();
    if (!irInterface_) {
        return ERROR_UNSUPPORTED_IR_EMITTER;
    }
    bool outRet = false;
    std::vector<ConsumerIrFreqRange> outRange;
    int32_t ret = irInterface_->GetCarrierFreqs(outRet, outRange);
    MMI_HILOGI("irInterface_->GetCarrierFreqs ret:%{public}d", ret);
    if (ret != RET_OK) {
        MMI_HILOGE("Infrared emitter GetCarrierFreqs failed:%{public}d", ret);
        return ret;
    }
    if (!outRet) {
        MMI_HILOGE("Infrared emitter GetCarrierFreqs out false");
        return RET_ERR;
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
    return RET_OK;
}

int32_t InfraredEmitterController::HasIrEmitter(bool &hasIrEmitter)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    InitInfraredEmitter();
    if (!irInterface_) {
        hasIrEmitter = false;
    } else {
        irInterface_->HasIrEmitter(hasIrEmitter);
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
