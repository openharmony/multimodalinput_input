/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INPUT_MANAGER_COMMAND_H
#define INPUT_MANAGER_COMMAND_H

#include <string>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class InputManagerCommand {
public:
    InputManagerCommand() = default;
    DISALLOW_COPY_AND_MOVE(InputManagerCommand);
    int32_t ParseCommand(int32_t argc, char *argv[]);
    int32_t ConnectService();
    void ShowUsage();
private:
    void InitializeMouseDeathStub();
    void SleepAndUpdateTime(int64_t &currentTimeMs);
    int32_t NextPos(int64_t begTimeMs, int64_t curtTimeMs, int32_t totalTimeMs, int32_t begPos, int32_t endPos);
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_MANAGER_COMMAND_H