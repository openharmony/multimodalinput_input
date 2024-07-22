/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "plugin_manager.h"

#include <string_view>

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "PluginManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

#if (defined(__aarch64__) || defined(__x86_64__))
constexpr std::string_view LIB_COOPERATE_PATH { "/system/lib64/libintention_cooperate.z.so" };
#else
constexpr std::string_view LIB_COOPERATE_PATH { "/system/lib/libintention_cooperate.z.so" };
#endif // defined(__x86_64__)

ICooperate* PluginManager::LoadCooperate()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    CHKPP(context_);
    if (cooperate_ == nullptr) {
        cooperate_ = LoadLibrary<ICooperate>(context_, LIB_COOPERATE_PATH.data());
    }
    return (cooperate_ != nullptr ? cooperate_->GetInstance() : nullptr);
}

void PluginManager::UnloadCooperate()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    cooperate_.reset();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
