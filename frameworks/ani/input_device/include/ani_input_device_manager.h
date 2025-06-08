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

#ifndef ANI_INPUT_DEVICE_MANAGER_H
#define ANI_INPUT_DEVICE_MANAGER_H

#include <memory>

#include "ani_event_target.h"

namespace OHOS {
namespace MMI {
class AniInputDeviceManager : public AniEventTarget {
public:
    AniInputDeviceManager() = default;
    DISALLOW_COPY_AND_MOVE(AniInputDeviceManager);
    ~AniInputDeviceManager() = default;

    void ResetEnv();
    void RegisterDevListener(ani_env *env, const std::string &type, ani_object handle);
};
} // namespace MMI
} // namespace OHOS
#endif // ANI_INPUT_DEVICE_MANAGER_H