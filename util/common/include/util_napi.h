/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef UTIL_NAPI_H
#define UTIL_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/log.h"

namespace OHOS {
namespace MMI {
#define CHKRV(env, state, desc) \
    do { \
        if ((state) != napi_ok) { \
            MMI_HILOGE("%{public}s failed", std::string(desc).c_str()); \
            auto infoTemp = std::string(__FUNCTION__)+ ": " + std::string(desc) + " failed"; \
            return; \
        } \
    } while (0)

#define CHKRV_SCOPE(env, state, desc, scope) \
    do { \
        if ((state) != napi_ok) { \
            MMI_HILOGE("%{public}s failed", std::string(desc).c_str()); \
            auto infoTemp = std::string(__FUNCTION__)+ ":" + std::string(desc) + " failed"; \
            napi_close_handle_scope(env, scope); \
            return; \
        } \
    } while (0)

#define CHKRP(env, state, desc) \
    do { \
        if ((state) != napi_ok) { \
            MMI_HILOGE("%{public}s failed", std::string(desc).c_str()); \
            auto infoTemp = std::string(__FUNCTION__)+ ": " + std::string(desc) + " failed"; \
            return nullptr; \
        } \
    } while (0)

#define CHKRF(env, state, desc) \
    do { \
        if ((state) != napi_ok) { \
            MMI_HILOGE("%{public}s failed", std::string(desc).c_str()); \
            auto infoTemp = std::string(__FUNCTION__)+ ": " + std::string(desc) + " failed"; \
            return false; \
        } \
    } while (0)

#define THROWERR(env, desc) \
    do { \
        MMI_HILOGE("%{public}s", (#desc)); \
        auto infoTemp = std::string(__FUNCTION__)+ ": " + #desc; \
        napi_throw_error(env, nullptr, infoTemp.c_str()); \
    } while (0)

namespace UtilNapi {
bool TypeOf(napi_env env, napi_value value, napi_valuetype type);
} // namespace UtilNapi
} // namespace MMI
} // namespace OHOS

#endif // UTIL_NAPI_H