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
    std::string eventType;
    std::string name;
    ani_ref callback = nullptr;
    int32_t subscribeId = 0;
    ani_ref keyOptionsObj = nullptr;
    std::shared_ptr<KeyOption> keyOption = nullptr;
    ~KeyEventMonitorInfo();
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
typedef std::map<std::string, std::list<std::shared_ptr<KeyEventMonitorInfo>>> Callbacks;
} // namespace MMI
} // namespace OHOS

#endif // ANI_INPUT_CONSUMER_H
