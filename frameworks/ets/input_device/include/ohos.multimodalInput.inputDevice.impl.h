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

#ifndef TAIHE_INPUT_DEVICE_IMPL_H
#define TAIHE_INPUT_DEVICE_IMPL_H

#include "taihe_input_device_utils.h"

namespace OHOS {
namespace MMI {
using TaiheDeviceListener = ohos::multimodalInput::inputDevice::DeviceListener;
using callbackTypes = std::variant<taihe::callback<void(TaiheDeviceListener const&)>>;
using TaihecType = ohos::multimodalInput::inputDevice::changedType;
using TaiheChangedType = ohos::multimodalInput::inputDevice::ChangedType;

struct CallbackObjects {
    CallbackObjects(callbackTypes cb, ani_ref ref) : callback(cb), ref(ref)
    {
    }
    ~CallbackObjects()
    {
        if (auto *env = taihe::get_env()) {
            env->GlobalReference_Delete(ref);
        }
    }
    callbackTypes callback;
    ani_ref ref;
};

class GlobalRefGuards {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuards(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }
    explicit operator bool() const
    {
        return ref_ != nullptr;
    }
    ani_ref get() const
    {
        return ref_;
    }
    ~GlobalRefGuards()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuards(const GlobalRefGuards &) = delete;
    GlobalRefGuards &operator=(const GlobalRefGuards &) = delete;
};
} // namespace MMI
} // namespace OHOS
#endif // TAIHE_INPUT_DEVICE_IMPL_H