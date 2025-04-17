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

#ifndef ANI_INPUT_CONSUMER_H
#define ANI_INPUT_CONSUMER_H

#include <ani.h>
#include <array>
#include <list>
#include <map>
#include <set>
#include <string>

#include "ani_util_common.h"
#include "key_option.h"

#define SUCCESS_CODE 0
#define ERROR_CODE (-1)
#define UNREGISTERED_CODE (-2)
#define PRE_KEY_MAX_COUNT 4

enum JS_CALLBACK_EVENT {
    JS_CALLBACK_EVENT_FAILED = -1,
    JS_CALLBACK_EVENT_SUCCESS = 1,
    JS_CALLBACK_EVENT_EXIST = 2,
    JS_CALLBACK_EVENT_NOT_EXIST = 3,
};

namespace OHOS {
namespace MMI {

struct KeyEventMonitorInfo {
    ani_env* env = nullptr;
    ani_vm *vm = nullptr;
    std::string eventType;
    std::string name;
    ani_ref callback = nullptr;
    int32_t subscribeId = 0;
    ani_ref keyOptionsObj = nullptr;
    std::shared_ptr<KeyOption> keyOption = nullptr;
    bool setCallback(ani_object callback);
    bool SetKeyOptionsObj(ani_object keyOptionsObj);
    ~KeyEventMonitorInfo();
};

enum AniErrorCode : int32_t {
    OTHER_ERROR = -1,
    COMMON_PERMISSION_CHECK_ERROR = 201,
    COMMON_PARAMETER_ERROR = 401,
    COMMON_USE_SYSAPI_ERROR = 202,
    INPUT_DEVICE_NOT_SUPPORTED = 801,
    INPUT_OCCUPIED_BY_SYSTEM = 4200002,
    INPUT_OCCUPIED_BY_OTHER = 4200003,
    PRE_KEY_NOT_SUPPORTED = 4100001,
    COMMON_DEVICE_NOT_EXIST = 3900001,
    COMMON_KEYBOARD_DEVICE_NOT_EXIST = 3900002,
    COMMON_NON_INPUT_APPLICATION = 3900003,
    ERROR_WINDOW_ID_PERMISSION_DENIED = 26500001,
};

typedef std::map<std::string, std::list<std::shared_ptr<KeyEventMonitorInfo>>> Callbacks;

class AniLocalScopeGuard {
public:
    AniLocalScopeGuard(ani_env *env, size_t nrRefs) : env_(env)
    {
        status_ = env_->CreateLocalScope(nrRefs);
    }

    ~AniLocalScopeGuard()
    {
        if (ANI_OK != status_) {
            return;
        }
        env_->DestroyLocalScope();
    }

    bool IsStatusOK()
    {
        return ANI_OK == status_;
    }

    ani_status GetStatus()
    {
        return status_;
    }

private:
    ani_env *env_ = nullptr;
    ani_status status_ = ANI_ERROR;
};

class ScopedAniEnv {
public:
    static expected<std::unique_ptr<ScopedAniEnv>, ani_status> Create(ani_vm *vm)
    {
        ani_env *env = nullptr;
        ani_options aniArgs {0, nullptr};
        auto status = vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
        if (ANI_OK != status) {
            status = vm->GetEnv(ANI_VERSION_1, &env);
            if (ANI_OK != status) {
                return status;
            }
        }

        auto scopedAniEnv = new ScopedAniEnv(vm, env);
        return std::unique_ptr<ScopedAniEnv>(scopedAniEnv);
    }

    static expected<std::unique_ptr<ScopedAniEnv>, ani_status> Create(ani_env *env)
    {
        ani_vm *vm = nullptr;
        auto status = env->GetVM(&vm);
        if (ANI_OK != status) {
            return status;
        }
        return Create(vm);
    }

    ~ScopedAniEnv()
    {
        if (vm_) {
            vm_->DetachCurrentThread();
            vm_ = nullptr;
        }
        env_ = nullptr;
    }

    ani_env *GetEnv()
    {
        return env_;
    }

    ScopedAniEnv(const ScopedAniEnv&) = delete;
    ScopedAniEnv& operator=(const ScopedAniEnv&) = delete;

private:
    ScopedAniEnv(ani_vm *vm, ani_env *env) : vm_(vm), env_(env)
    {
    }

private:
    ani_vm *vm_ = nullptr;
    ani_env *env_ = nullptr;
};
} // namespace MMI
} // namespace OHOS

#endif // ANI_INPUT_CONSUMER_H
