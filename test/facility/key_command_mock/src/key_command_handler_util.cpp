/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "key_command_handler_util.h"

namespace OHOS {
namespace MMI {
namespace {
OHOS::MMI::IKeyCommandHandlerUtil *g_instance = nullptr;
} // namespace

IKeyCommandHandlerUtil::IKeyCommandHandlerUtil()
{
    g_instance = this;
}

bool IsSpecialType(int32_t keyCode, SpecialType type)
{
    return (g_instance != nullptr ? g_instance->IsSpecialType(keyCode, type) : false);
}
} // namespace MMI
} // namespace OHOS
