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

#include "ani_input_device_manager.h"

#include "input_device_impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniInputDeviceManager"

namespace OHOS {
namespace MMI {

void AniInputDeviceManager::RegisterDevListener(ani_env *env, const std::string &type, ani_object handle)
{
    CALL_DEBUG_ENTER;
    AddListener(env, type, handle);
}

void AniInputDeviceManager::ResetEnv()
{
    CALL_DEBUG_ENTER;
    AniEventTarget::ResetEnv();
}
} // namespace MMI
} // namespace OHOS