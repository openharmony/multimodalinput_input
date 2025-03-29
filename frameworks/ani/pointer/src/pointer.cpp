 /*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "pointer.h"
#include <iostream>

#include "define_multimodal.h"
#include "mmi_log.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniPointer"

using namespace OHOS::MMI;

namespace {
constexpr int32_t ANI_SCOPE_SIZE = 16;
constexpr int32_t MILLISECOND_FACTOR = 1000;
constexpr size_t EVENT_NAME_LEN { 64 };
constexpr size_t PRE_KEYS_SIZE { 4 };
constexpr size_t INPUT_PARAMETER_MIDDLE { 2 };
constexpr size_t INPUT_PARAMETER_MAX { 3 };
constexpr int32_t OCCUPIED_BY_SYSTEM = -3;
constexpr int32_t OCCUPIED_BY_OTHER = -4;
const double INT32_MAX_D = static_cast<double>(std::numeric_limits<int32_t>::max());
} // namespace

static int SetPointerStyleInner(ani_env *env, ani_object context, ani_object idObj, ani_enum_item enumObj)
{
    return 0;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        MMI_HILOGE("%{public}s: Unsupported ANI_VERSION_1", __func__);
        return ANI_ERROR;
    }

    static const char *name = "L@ohos/multimodalInput/pointer/pointer;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(name, &ns)) {
        MMI_HILOGE("%{public}s: Not found %{public}s", __func__, name);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"setPointerStyleInner", nullptr, reinterpret_cast<void *>(SetPointerStyleInner)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        MMI_HILOGE("%{public}s:Cannot bind native methods to '%{public}s'", __func__, name);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}