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

#ifndef POINTER_DEVICE_MANAGER_H
#define POINTER_DEVICE_MANAGER_H

#include "delegate_interface.h"

namespace OHOS {
namespace MMI {
class PointerDeviceManager {
public:
    DISALLOW_COPY_AND_MOVE(PointerDeviceManager);

    static PointerDeviceManager& GetInstance();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy);
    std::shared_ptr<DelegateInterface> GetDelegateProxy();
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

public:
    std::atomic<bool> isInit { false };
    std::atomic<bool> isFirstAddCommonEventService { true };
    std::atomic<bool> isFirstAddRenderService { true };
    std::atomic<bool> isFirstAddDisplayManagerService { true };
    std::atomic<bool> isFirstAdddistributedKVDataService { true };
    std::atomic<bool> isInitDefaultMouseIconPath { false };
    std::atomic<bool> isPointerVisible { false };
    std::atomic<int32_t> mouseId_ { 0 };
    std::string mouseIcons_;
    std::atomic<bool> mouseDisplayState { false };
private:
    PointerDeviceManager() = default;
    ~PointerDeviceManager() = default;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    std::shared_ptr<DelegateInterface> delegateProxy_ { nullptr };
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
};

#define POINTER_DEV_MGR ::OHOS::MMI::PointerDeviceManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // POINTER_DEVICE_MANAGER_H
