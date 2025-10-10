/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ohos.multimodalInput.inputDevice.ani.hpp"
#include "define_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "inputDevice_ani_constructor"

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    CHKPR(vm, ANI_ERROR);
    CHKPR(result, ANI_ERROR);
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        MMI_HILOGE("Failed to get ANI environment");
        return ANI_ERROR;
    }
    if (ANI_OK != ohos::multimodalInput::inputDevice::ANIRegister(env)) {
        MMI_HILOGE("Error from ohos::multimodalInput::inputDevice::ANIRegister");
        return ANI_ERROR;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}