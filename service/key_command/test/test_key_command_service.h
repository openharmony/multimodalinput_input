/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#ifndef TEST_KEY_COMMAND_SERVICE_H
#define TEST_KEY_COMMAND_SERVICE_H

#include <string>
#include "i_key_command_service.h"
#include "key_command_context.h"

namespace OHOS {
namespace MMI {
class TestKeyCommandService : public IKeyCommandService {
public:
    TestKeyCommandService() = default;
    virtual ~TestKeyCommandService() = default;

    void HandleSosAbilityLaunched() override {}
    void SetupSosDelayTimer() override {}
    void ClearSpecialKeys() override {}
    void ResetLaunchAbilityCount() override {}
    void ClearRepeatKeyCountMap() override {}
    uint32_t GetScreenCapturePermission() override
    {
        return 0;
    }
    int32_t GetRetValue() override
    {
        return -1;
    }
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    void UnregisterMistouchPrevention() override {}
    void CallMistouchPrevention() override {}
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION

    void HandleSpecialKeys(int32_t keyCode, int32_t keyAction) override {}
    bool HasScreenCapturePermission(uint32_t permissionType) override
    {
        return false;
    }
};
} // namespace MMI
} // namespace OHOS
#endif // TEST_KEY_COMMAND_SERVICE_H