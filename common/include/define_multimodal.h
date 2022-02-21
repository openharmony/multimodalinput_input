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

#include "log.h"

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
            MMI_LOGE("%{public}s, (%{public}d), CHKPL(%{public}s) is null, do nothing", \
                __FILE__, __LINE__, #cond); \
        } \
    } while (0)

#define CHKPV(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKPV(%{public}s) is null", \
                __FILE__, __LINE__, #cond); \
            return; \
        } \
    } while (0)

#define CHKPF(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKPF(%{public}s) is null", \
                __FILE__, __LINE__, #cond); \
            return false; \
        } \
    } while (0)

#define CHKPC(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKPC(%{public}s) is null, skip then continue", \
                __FILE__, __LINE__, #cond); \
            continue; \
        } \
    } while (0)

#define CHKPB(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKPC(%{public}s) is null, skip then break", \
                __FILE__, __LINE__, #cond); \
            continue; \
        } \
    } while (0)

#define CHKPR(cond, r) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKPR(%{public}s) is null, return value is %{public}d", \
                __FILE__, __LINE__, #cond, r); \
            return r; \
        } \
    } while (0)

#define CHKPP(cond, r) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKPP(%{public}s) is null, return value is null", \
                __FILE__, __LINE__, #cond); \
            return r; \
        } \
    } while (0)

#define CK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("%{public}s, (%{public}d), CK(%{public}s), errCode:%{public}d", \
                __FILE__, __LINE__, #cond, ec); \
        } \
    } while (0)

#define CHK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("%{public}s, (%{public}d), CHK(%{public}s), errCode:%{public}d", \
                __FILE__, __LINE__, #cond, ec); \
            return; \
        } \
    } while (0)

#define CHKF(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKF(%{public}s), errCode:%{public}d", \
                __FILE__, __LINE__, #cond, ec); \
            return false; \
        } \
    } while (0)

#define CHKC(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKC(%{public}s), errCode:%{public}d", \
                __FILE__, __LINE__, #cond, ec); \
            continue; \
        } \
    } while (0)

#define CHKR(cond, ec, r) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("%{public}s, (%{public}d), CHKR(%{public}s), errCode:%{public}d", \
                __FILE__, __LINE__, #cond, ec); \
            return r; \
        } \
    } while (0)

#else // DEBUG_CODE_TEST
#define CHKPL(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("CHKPL(%{public}s) is null, do nothing", #cond); \
        } \
    } while (0)

#define CHKPV(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("CHKPV(%{public}s) is null", #cond); \
            return; \
        } \
    } while (0)

#define CHKPF(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("CHKPF(%{public}s) is null", #cond); \
            return false; \
        } \
    } while (0)

#define CHKPC(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("CHKPC(%{public}s) is null, skip then continue", #cond); \
            continue; \
        } \
    } while (0)

#define CHKPB(cond, ...) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("CHKPC(%{public}s) is null, skip then break", #cond); \
            continue; \
        } \
    } while (0)

#define CHKPR(cond, r) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("CHKPR(%{public}s) is null, return value is %{public}d", #cond, r); \
            return r; \
        } \
    } while (0)

#define CHKPP(cond, r) \
    do { \
        if ((cond) == nullptr) { \
            MMI_LOGE("CHKPP(%{public}s) is null, return value is null", #cond); \
            return r; \
        } \
    } while (0)

#define CK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("CK(%{public}s), errCode:%{public}d", #cond, ec); \
        } \
    } while (0)

#define CHK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("CHK(%{public}s), errCode:%{public}d", #cond, ec); \
            return; \
        } \
    } while (0)

#define CHKF(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("CHKF(%{public}s), errCode:%{public}d", #cond, ec); \
            return 0; \
        } \
    } while (0)

#define CHKC(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("CHKC(%{public}s), errCode:%{public}d", #cond, ec); \
            continue; \
        } \
    } while (0)

#define CHKR(cond, ec, r) \
    do { \
        if (!(cond)) { \
            MMI_LOGE("CHKR(%{public}s), errCode:%{public}d", #cond, ec); \
            return r; \
        } \
    } while (0)

#endif
#endif // DEFINE_MULTIMODAL_H