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

enum AniErrorCode : int32_t {
    COMMON_PARAMETER_ERROR = 401,
    COMMON_USE_SYSAPI_ERROR = 202,
};

static void ThrowBusinessError(ani_env *env, int errCode, std::string&& errMsg)
{
    MMI_HILOGD("Begin ThrowBusinessError.");
    static const char *errorClsName = "L@ohos/base/BusinessError;";
    ani_class cls {};
    if (ANI_OK != env->FindClass(errorClsName, &cls)) {
        MMI_HILOGE("find class BusinessError %{public}s failed", errorClsName);
        return;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":V", &ctor)) {
        MMI_HILOGE("find method BusinessError.constructor failed");
        return;
    }
    ani_object errorObject;
    if (ANI_OK != env->Object_New(cls, ctor, &errorObject)) {
        MMI_HILOGE("create BusinessError object failed");
        return;
    }
    ani_double aniErrCode = static_cast<ani_double>(errCode);
    ani_string errMsgStr;
    if (ANI_OK != env->String_NewUTF8(errMsg.c_str(), errMsg.size(), &errMsgStr)) {
        MMI_HILOGE("convert errMsg to ani_string failed");
        return;
    }
    if (ANI_OK != env->Object_SetFieldByName_Double(errorObject, "code", aniErrCode)) {
        MMI_HILOGE("set error code failed");
        return;
    }
    if (ANI_OK != env->Object_SetPropertyByName_Ref(errorObject, "message", errMsgStr)) {
        MMI_HILOGE("set error message failed");
        return;
    }
    env->ThrowError(static_cast<ani_error>(errorObject));
    return;
}

static int32_t ToInt32ECMAScript(double value)
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
        ThrowBusinessError(env, COMMON_PARAMETER_ERROR, "Windowid is invalid");
        return 0;
    }

    int32_t pointerStyleID = ParseEnumToInt(env, pointerStyle);
    if ((pointerStyleID < DEFAULT && pointerStyleID != DEVELOPER_DEFINED_ICON) || pointerStyleID > RUNNING) {
        MMI_HILOGE("Undefined pointer style");
        ThrowBusinessError(env, COMMON_PARAMETER_ERROR, "Pointer style does not exist");
        return 0;
    }

    PointerStyle style;
    style.id = pointerStyleID;
    int32_t errorCode = InputManager::GetInstance()->SetPointerStyle(windowid, style);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("The windowId is negative number and no system applications use system API");
        ThrowBusinessError(env, COMMON_USE_SYSAPI_ERROR,
            "windowId is negative number and no system applications use system API");
        return 0;
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