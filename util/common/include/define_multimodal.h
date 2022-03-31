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
#ifndef DEFINE_MULTIMODAL_H
#define DEFINE_MULTIMODAL_H

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
#ifndef RET_OK
    #define RET_OK (0)
#endif

#ifndef RET_ERR
    #define RET_ERR (-1)
#endif

#ifndef LINEINFO
#define LINEINFO __FILE__, __LINE__
#endif

#if defined(__GNUC__) && __GNUC__ >= 4
    #define WL_EXPORT __attribute__ ((visibility("default")))
#else
    #define WL_EXPORT
#endif

#ifdef DEBUG_CODE_TEST
#define CHKPL(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("%{public}s, (%{public}d), CHKPL(%{public}s) is null, do nothing", \
                __FILE__, __LINE__, #cond); \
        } \
    } while (0)

#define CHKPV(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("%{public}s, (%{public}d), CHKPV(%{public}s) is null", \
                __FILE__, __LINE__, #cond); \
            return; \
        } \
    } while (0)

#define CHKPF(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("%{public}s, (%{public}d), CHKPF(%{public}s) is null", \
                __FILE__, __LINE__, #cond); \
            return false; \
        } \
    } while (0)

#define CHKPC(cond) \
    { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("%{public}s, (%{public}d), CHKPC(%{public}s) is null, skip then continue", \
                __FILE__, __LINE__, #cond); \
            continue; \
        } \
    }

#define CHKPB(cond) \
    { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("%{public}s, (%{public}d), CHKPC(%{public}s) is null, skip then break", \
                __FILE__, __LINE__, #cond); \
            break; \
        } \
    }

#define CHKPR(cond, r) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("%{public}s, (%{public}d), CHKPR(%{public}s) is null, return value is %{public}d", \
                __FILE__, __LINE__, #cond, r); \
            return r; \
        } \
    } while (0)

#define CHKPP(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("%{public}s, (%{public}d), CHKPP(%{public}s) is null, return value is null", \
                __FILE__, __LINE__, #cond); \
            return nullptr; \
        } \
    } while (0)

#define CK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_HILOGE("%{public}s, (%{public}d), CK(%{public}s), errCode:%{public}d", \
                __FILE__, __LINE__, #cond, ec); \
        } \
    } while (0)

#define CHK_PIDANDTID() \
    do { \
        MMI_HILOGD("%{public}s, (%{public}d), pid:%{public}d threadId:%{public}" PRIu64, \
            __FILE__, __LINE__, GetPid(), GetThisThreadId()); \
    } while (0)

#else // DEBUG_CODE_TEST
#define CHKPL(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("CHKPL(%{public}s) is null, do nothing", #cond); \
        } \
    } while (0)

#define CHKPV(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("CHKPV(%{public}s) is null", #cond); \
            return; \
        } \
    } while (0)

#define CHKPF(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("CHKPF(%{public}s) is null", #cond); \
            return false; \
        } \
    } while (0)

#define CHKPC(cond) \
    { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("CHKPC(%{public}s) is null, skip then continue", #cond); \
            continue; \
        } \
    }

#define CHKPB(cond) \
    { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("CHKPB(%{public}s) is null, skip then break", #cond); \
            break; \
        } \
    }

#define CHKPR(cond, r) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("CHKPR(%{public}s) is null, return value is %{public}d", #cond, r); \
            return r; \
        } \
    } while (0)

#define CHKPP(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("CHKPP(%{public}s) is null, return value is null", #cond); \
            return nullptr; \
        } \
    } while (0)

#define CK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_HILOGE("CK(%{public}s), errCode:%{public}d", #cond, ec); \
        } \
    } while (0)

#define CHK_PIDANDTID() \
    do { \
        MMI_HILOGD("pid:%{public}d threadId:%{public}" PRIu64, GetPid(), GetThisThreadId()); \
    } while (0)

#endif
} // namespace MMI
} // namespace OHOS
#endif // DEFINE_MULTIMODAL_H