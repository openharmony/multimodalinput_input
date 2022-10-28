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
#ifndef UTIL_EX_H
#define UTIL_EX_H

#include <ctime>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#include "securec.h"

#include "define_multimodal.h"
#include "mmi_log.h"
#include "struct_multimodal.h"
#include "util.h"

namespace OHOS {
namespace MMI {
template<class ...Ts>
int32_t mprintf(int32_t fd, const char* fmt, Ts... args)
{
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UtilEx" };
    if (fmt == nullptr) {
        return RET_ERR;
    }

    static constexpr size_t bufSize = 1024 * 10;
    char buf[bufSize] = {};
    int32_t ret = snprintf_s(buf, bufSize, bufSize - 1, fmt, args...);
    if (ret == -1) {
        return ret;
    }

    if (fd < 0) {
        ret = printf("%s\n", buf);
    } else if (fd == 0) {
        MMI_HILOGF("%{public}s", buf);
    } else {
        ret = dprintf(fd, "%s\n", buf);
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS
#endif // UTIL_EX_H