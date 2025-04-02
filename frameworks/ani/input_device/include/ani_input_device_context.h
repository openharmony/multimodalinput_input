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

#ifndef ANI_MULTI_MODAL_INPUT_DEVICE_H
#define ANI_MULTI_MODAL_INPUT_DEVICE_H

#include "ani_input_device_manager.h"

namespace OHOS {
namespace MMI {
class AniInputDeviceContext final {
public:
    AniInputDeviceContext();
    DISALLOW_COPY_AND_MOVE(AniInputDeviceContext);
    ~AniInputDeviceContext();

    void On(ani_env *env, ani_string info, ani_object callback);

private:
    std::shared_ptr<AniInputDeviceManager> mgr_ { nullptr };
    std::mutex mtx_;
};
} // namespace MMI
} // namespace OHOS
#endif // ANI_MULTI_MODAL_INPUT_DEVICE_H
