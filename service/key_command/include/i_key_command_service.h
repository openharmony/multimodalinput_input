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

#ifndef I_KEY_COMMAND_SERVICE_H
#define I_KEY_COMMAND_SERVICE_H
  
#include <memory>
#include "key_event.h"

namespace OHOS {
namespace MMI {
class IKeyCommandService {
public:
    virtual void HandleSosAbilityLaunched() = 0;
    virtual void SetupSosDelayTimer() = 0;
    virtual void ClearSpecialKeys() = 0;
    virtual void ResetLaunchAbilityCount() = 0;
    virtual void ClearRepeatKeyCountMap() = 0;
    virtual uint32_t GetScreenCapturePermission() = 0;
    virtual int32_t GetRetValue() = 0;

#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    virtual void UnregisterMistouchPrevention() = 0;
    virtual void CallMistouchPrevention() = 0;
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    virtual void HandleSpecialKeys(int32_t keyCode, int32_t keyAction) = 0;
    virtual bool HasScreenCapturePermission(uint32_t permissionType) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_KEY_COMMAND_SERVICE_H
