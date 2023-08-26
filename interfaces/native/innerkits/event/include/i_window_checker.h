/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef I_WINDOW_CHECKER_H
#define I_WINDOW_CHECKER_H

#include <memory>

namespace OHOS {
namespace MMI {
struct IWindowChecker {
public:
    IWindowChecker() = default;
    virtual ~IWindowChecker() = default;

    virtual int32_t CheckWindowId(int32_t windowId) const = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_WINDOW_CHECKER_H
