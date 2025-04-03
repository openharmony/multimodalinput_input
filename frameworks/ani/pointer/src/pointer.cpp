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
#include "input_manager.h"
#include "mmi_log.h"

#include <cstdint>
#include <cmath>
#include <limits>

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

enum NapiErrorCode : int32_t {
    COMMON_PARAMETER_ERROR = 401,
    COMMON_USE_SYSAPI_ERROR = 202,
};

static ani_error CreateAniError(ani_env *env, std::string&& errMsg)
{
    static const char *errorClsName = "Lescompat/Error;";
    ani_class cls {};
    if (ANI_OK != env->FindClass(errorClsName, &cls)) {
        MMI_HILOGE("%{public}s: Not found namespace %{public}s.", __func__, errorClsName);
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;:V", &ctor)) {
        MMI_HILOGE("%{public}s: Not found <ctor> in %{public}s.", __func__, errorClsName);
        return nullptr;
    }
    ani_string error_msg;
    env->String_NewUTF8(errMsg.c_str(), errMsg.size(), &error_msg);
    ani_object errorObject;
    env->Object_New(cls, ctor, &errorObject, error_msg);
    return static_cast<ani_error>(errorObject);
}

int32_t ToInt32ECMAScript(double value)
{
    if (std::isnan(value) || std::isinf(value)) {
        return 0;
    }

    double truncated = std::trunc(value);
    double modValue = std::fmod(truncated, 4294967296.0);
    uint32_t uint32Val = static_cast<uint32_t>(modValue);
    return static_cast<int32_t>(uint32Val);
}

static ani_int ParseEnumToInt(ani_env *env, ani_enum_item enumItem)
{
    ani_int intValue = -1;
    if (ANI_OK != env->EnumItem_GetValue_Int(enumItem, &intValue)) {
        MMI_HILOGE("%{public}s: EnumItem_GetValue_Int FAILD.", __func__);
        return -1;
    }
    MMI_HILOGD("%{public}s: Enum Value: %{public}d.", __func__, intValue);
    return intValue;
}

static int SetPointerStyleInner(ani_env *env, ani_double windowid, ani_enum_item pointerStyle)
{
    int32_t windowID = ToInt32ECMAScript(static_cast<double>(windowid));
    if (windowID < 0 && windowID != GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowid");
        ani_error err = CreateAniError(env, "Windowid is invalid");
        env->ThrowError(err);
        return COMMON_PARAMETER_ERROR;
    }

    int32_t pointerStyleID = ParseEnumToInt(env, pointerStyle);
    if ((pointerStyleID < DEFAULT && pointerStyleID != DEVELOPER_DEFINED_ICON) || pointerStyleID > RUNNING) {
        MMI_HILOGE("Undefined pointer style");
        ani_error err = CreateAniError(env, "Pointer style does not exist");
        env->ThrowError(err);
        return COMMON_PARAMETER_ERROR;
    }

    PointerStyle style;
    style.id = pointerStyleID;
    int32_t errorCode = InputManager::GetInstance()->SetPointerStyle(windowid, style);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("The windowId is negative number and no system applications use system API");
        ani_error err = CreateAniError(env, "windowId is negative number and no system applications use system API");
        env->ThrowError(err);
        return COMMON_USE_SYSAPI_ERROR;
    }
    MMI_HILOGD(" SetPointerStyleInner end.");
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