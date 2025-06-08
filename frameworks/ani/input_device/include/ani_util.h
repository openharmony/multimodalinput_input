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

#ifndef ANI_UTIL_H
#define ANI_UTIL_H
#include <ani.h>

#include "input_device.h"

namespace OHOS {
namespace MMI {
class AniUtil {
public:
    struct ReportData {
        ani_ref ref { nullptr };
        int32_t deviceId { 0 };
    };
    struct CallbackInfo {
        ani_env *env_ { nullptr };
        ani_ref callback_ { nullptr };
        bool SetCallback(ani_object handle);
        ~CallbackInfo();
    };
    struct DeviceType {
        std::string sourceTypeName;
        uint32_t typeBit { 0 };
    };

    static bool IsSameHandle(ani_env *env, ani_ref handle, ani_env *iterEnv, ani_ref iterhandle);
    static ani_string StdStringToANIString(ani_env* env, const std::string& str);
    static ani_boolean IsInstanceOf(ani_env *env, const std::string &cls_name, ani_object obj);
    static ani_object CreateAniObject(ani_env *env, const char *nsName, const char *className);
};

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
} // namespace MMI
} // namespace OHOS
#endif // ANI_UTIL_H