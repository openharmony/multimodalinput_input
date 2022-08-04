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

#ifndef INJECTION_TOOLS_HELP_FUNC_H
#define INJECTION_TOOLS_HELP_FUNC_H

#include <cstring>

#include "nocopyable.h"

#include "util.h"

namespace OHOS {
namespace MMI {
class InjectionToolsHelpFunc {
public:
    InjectionToolsHelpFunc() = default;
    DISALLOW_COPY_AND_MOVE(InjectionToolsHelpFunc);
    std::string GetHelpText();
};
} // namespace MMI
} // namespace OHOS
#endif // INJECTION_TOOLS_HELP_FUNC_H