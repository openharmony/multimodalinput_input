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

#include "gesturesense_wrapper.h"

#include <dlfcn.h>

#include "define_multimodal.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GesturesenseWrapper"

namespace OHOS {
namespace MMI {
namespace {
const char* GESTURESENSE_WRAPPER_PATH = "libgesture.z.so";
} // namespace

GesturesenseWrapper::GesturesenseWrapper() {}

GesturesenseWrapper::~GesturesenseWrapper()
{
    CALL_INFO_TRACE;
    CHKPV(gesturesenseWrapperHandle_);
    dlclose(gesturesenseWrapperHandle_);
    gesturesenseWrapperHandle_ = nullptr;
}

void GesturesenseWrapper::InitGestureSenseWrapper()
{
    CALL_INFO_TRACE;
    gesturesenseWrapperHandle_ = dlopen(GESTURESENSE_WRAPPER_PATH, RTLD_NOW);
    if (gesturesenseWrapperHandle_ == nullptr) {
        MMI_HILOGE("libgesture.z.so was not loaded, path:%{private}s, error:%{public}s",
            GESTURESENSE_WRAPPER_PATH, dlerror());
        goto fail;
        return;
    }
    touchUp_ = (TOUCH_UP)dlsym(gesturesenseWrapperHandle_, "TouchUp");
    if (touchUp_ == nullptr) {
        MMI_HILOGE("Gesturesense wrapper symbol failed, touchUp_ error:%{public}s", dlerror());
        goto fail;
        return;
    }
    getBoundingSquareness_ = (GET_BOUNDING_SQUARENESS)dlsym(gesturesenseWrapperHandle_, "GetBoundingSquareness");
    if (getBoundingSquareness_ == nullptr) {
        MMI_HILOGE("Gesturesense wrapper symbol failed, getBoundingSquareness_ error:%{public}s", dlerror());
        goto fail;
        return;
    }
    MMI_HILOGI("Gesturesense wrapper init success");
    return;
fail:
    dlclose(gesturesenseWrapperHandle_);
}
} // namespace MMI
} // namespace OHOS