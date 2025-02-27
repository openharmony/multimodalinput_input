/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "fingersense_wrapper.h"

#include <dlfcn.h>

#include "define_multimodal.h"
#include "pointer_event.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FingersenseWrapper"

namespace OHOS {
namespace MMI {
namespace {
const char* FINGERSENSE_WRAPPER_PATH { "libfingersense_wrapper.z.so" };
constexpr int32_t MAX_TOUCH_INFO_SIZE = 10;
} // namespace

FingersenseWrapper::FingersenseWrapper() {}
FingersenseWrapper::~FingersenseWrapper()
{
    CALL_DEBUG_ENTER;
    CHKPV(fingerSenseWrapperHandle_);
    MMI_HILOGD("Start release fingersense wrapper");
    dlclose(fingerSenseWrapperHandle_);
    fingerSenseWrapperHandle_ = nullptr;
    touchInfos_.clear();
}

void FingersenseWrapper::InitFingerSenseWrapper()
{
    CALL_DEBUG_ENTER;
    fingerSenseWrapperHandle_ = dlopen(FINGERSENSE_WRAPPER_PATH, RTLD_NOW);
    if (fingerSenseWrapperHandle_ == nullptr) {
        MMI_HILOGE("libfingersense_wrapper.z.so was not loaded, error:%{public}s", dlerror());
        return;
    }

    setCurrentToolType_ = (SET_CURRENT_TOOL_TYPE)dlsym(fingerSenseWrapperHandle_, "SetCurrentToolType");
    notifyTouchUp_ = (NOTIFY_TOUCH_UP)dlsym(fingerSenseWrapperHandle_, "NotifyTouchUp");
    enableFingersense_ = (ENABLE_FINGERSENSE)dlsym(fingerSenseWrapperHandle_, "EnableFingersense");
    disableFingerSense_ = (DISABLE_FINGERSENSE)dlsym(fingerSenseWrapperHandle_, "DisableFingerSense");
    if (setCurrentToolType_ == nullptr || notifyTouchUp_ == nullptr || enableFingersense_ == nullptr ||
        disableFingerSense_ == nullptr) {
        MMI_HILOGE("Fingersense wrapper symbol failed, error:%{public}s", dlerror());
        dlclose(fingerSenseWrapperHandle_);
        return;
    }

    sendFingerSenseDisplayMode_ = (SEND_FINGERSENSE_DISPLAYMODE)dlsym(fingerSenseWrapperHandle_, "UpdateDisplayMode");
    if (sendFingerSenseDisplayMode_ == nullptr) {
        MMI_HILOGE("Send fingersense display mode symbol failed, error:%{public}s", dlerror());
        dlclose(fingerSenseWrapperHandle_);
        return;
    }
    MMI_HILOGD("Fingersense wrapper init success");
}

void FingersenseWrapper::SaveTouchInfo(float pointX, float pointY, int32_t toolType)
{
    std::lock_guard<std::mutex> guard(lock_);
    while (touchInfos_.size() >= MAX_TOUCH_INFO_SIZE) {
        touchInfos_.erase(touchInfos_.begin());
    }
    TouchInfo touchInfo;
    touchInfo.x = pointX;
    touchInfo.y = pointY;
    touchInfo.touch_type = toolType;
    touchInfos_.push_back(touchInfo);
}

bool FingersenseWrapper::IsEqual(float a, float b, float epsilon)
{
    return fabs(a - b) < epsilon;
}

int32_t FingersenseWrapper::CheckKnuckleEvent(float pointX, float pointY, bool &isKnuckleType)
{
    std::lock_guard<std::mutex> guard(lock_);
    for (size_t i = 0; i < touchInfos_.size(); i++) {
        TouchInfo touchInfo = touchInfos_[i];
        if (IsEqual(touchInfo.x, pointX) && IsEqual(touchInfo.y, pointY)) {
            isKnuckleType = touchInfo.touch_type == MMI::PointerEvent::TOOL_TYPE_KNUCKLE;
            return RET_OK;
        }
    }
    return RET_ERR;
}
} // namespace MMI
} // namespace OHOS