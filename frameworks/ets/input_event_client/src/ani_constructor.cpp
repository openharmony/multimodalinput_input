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
#include "mmi_log.h"
#include "ohos.multimodalInput.inputEventClient.ani.hpp"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "aniInputEventClientCtor"

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (!vm) {
        MMI_HILOGE("vm is null");
        return ANI_ERROR;
    }
    if (!result) {
        MMI_HILOGE("result is null");
        return ANI_ERROR;
    }
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        MMI_HILOGE("Failed to get ANI environment");
        return ANI_ERROR;
    }
    int32_t ret = ohos::multimodalInput::inputEventClient::ANIRegister(env);
    if (ret != ANI_OK) {
        MMI_HILOGE("ANIRegister failed, error: %{public}d", ret);
        return ANI_ERROR;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}