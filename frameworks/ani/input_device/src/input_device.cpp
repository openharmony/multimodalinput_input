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

#include "input_device.h"
#include <iostream>

#include "define_multimodal.h"
#include "mmi_log.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniInputDevice"

static ani_object CreateDeviceInfoObj(ani_env *env)
{
    ani_namespace ns {};
    if (ANI_OK != env->FindNamespace("L@@ohos/multimodalInput/inputDevice/inputDevice;", &ns)) {
        MMI_HILOGE("Not found namespace 'LinputDevice'");
        return nullptr;
    }

    static const char *className = "LInputDeviceDataImpl;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        MMI_HILOGE("Not found className %{public}s.", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        MMI_HILOGE("get ctor Failed %{public}s.'", className);
        return nullptr;
    }
    ani_object prefencesObj = nullptr;
    int64_t nativePtr = 0;
    if (ANI_OK != env->Object_New(cls, ctor, &prefencesObj, reinterpret_cast<ani_long>(nativePtr))) {
        MMI_HILOGE("Create Object Failed %{public}s.", className);
        return nullptr;
    }
    MMI_HILOGI("Create DeviceInfoObj succeed.");
    return prefencesObj;
}

static ani_object DoubleToObject(ani_env *env, double value)
{
    ani_object aniObject = nullptr;
    ani_double doubleValue = static_cast<ani_double>(value);
    static const char *className = "Lstd/core/Double;";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        MMI_HILOGE("Not found '%{public}s'.", className);
        return aniObject;
    }
    ani_method objCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "D:V", &objCtor)) {
        MMI_HILOGE("Class_GetMethod Failed '%{public}s <ctor>.'", className);
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, objCtor, &aniObject, doubleValue)) {
        MMI_HILOGE("Object_New Failed '%{public}s. <ctor>", className);
        return aniObject;
    }
    return aniObject;
}

static ani_object DoubleArrayToObject(ani_env *env, const std::vector<double> values)
{
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("Lescompat/Array;", &arrayCls)) {
        MMI_HILOGE("FindClass Lescompat/Array; Failed");
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        MMI_HILOGE("Class_FindMethod <ctor> Failed");
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        MMI_HILOGE("Object_New Array Faild");
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_object aniValue = DoubleToObject(env, value);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, aniValue)) {
            MMI_HILOGI("Object_CallMethodByName_Void  $_set Faild ");
            break;
        }
        index++;
    }
    return arrayObj;
}

static ani_object GetDeviceList(ani_env *env, ani_object obj)
{
    std::vector<double> values;
    ani_object object = DoubleArrayToObject(env, values);
    return object;
}

static ani_object GetDeviceInfo(ani_env *env, ani_object obj)
{
    ani_object object = CreateDeviceInfoObj(env);
    return object;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        MMI_HILOGE("%{public}s: Unsupported ANI_VERSION_1", __func__);
        return ANI_ERROR;
    }

    static const char *name = "L@ohos/multimodalInput/inputDevice/inputDevice;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(name, &ns)) {
        MMI_HILOGE("%{public}s: Not found %{public}s", __func__, name);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"getDeviceListInner", nullptr, reinterpret_cast<void *>(GetDeviceList)},
        ani_native_function {"getDeviceInfoInner", nullptr, reinterpret_cast<void *>(GetDeviceInfo)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        MMI_HILOGE("%{public}s:Cannot bind native methods to '%{public}s'", __func__, name);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}