/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
{}
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

#include "init_param.h"

namespace OHOS {
namespace MMI {
namespace {
IInitParam *g_instance = nullptr;
} // namespace

IInitParam::IInitParam()
{
    g_instance = this;
}

extern "C" int SystemReadParam(const char *name, char *value, uint32_t *len)
{
    if (g_instance == nullptr) {
        return -1;
    }
    return g_instance->SystemReadParam(name, value, len);
}
} // namespace MMI
} // namespace OHOS