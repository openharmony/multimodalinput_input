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

#include "pointer_device_manager.h"

#define MMI_LOG_TAG "InputDeviceManager"

namespace OHOS {
namespace MMI {
PointerDeviceManager& PointerDeviceManager::GetInstance()
{
    static PointerDeviceManager instance;
    return instance;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
void PointerDeviceManager::SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy)
{
    delegateProxy_ = proxy;
}

std::shared_ptr<DelegateInterface> PointerDeviceManager::GetDelegateProxy()
{
    return delegateProxy_;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
} // namespace MMI
} // namespace OHOS
