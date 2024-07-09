/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

inline constexpr int32_t INVALID_FD { -1 };
inline constexpr int32_t INVALID_PID { -1 };

#ifndef LINEINFO
#define LINEINFO __FILE__, __LINE__
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

#define CHKPS(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("%{public}s, (%{public}d), CHKPS(%{public}s) is null", \
                __FILE__, __LINE__, #cond); \
            return ""; \
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
            MMI_HILOGW("%{public}s, (%{public}d), CHKPB(%{public}s) is null, skip then break", \
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

#define CHKPO(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("%{public}s, (%{public}d), CHKPO(%{public}s) is null, skip then continue", \
                __FILE__, __LINE__, #cond); \
            return {}; \
        } \
    } while (0)

#define CK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_HILOGE("%{public}s, (%{public}d), CK(%{public}s), errCode:%{public}d", \
                __FILE__, __LINE__, #cond, ec); \
        } \
    } while (0)

#define CHK_PID_AND_TID() \
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

#define CHK_INVALID_RV(cond, desc) \
    do { \
        if ((cond) < 0) { \
            MMI_HILOGE("(%{public}s less than 0, desc:%{public}s)", #cond, std::string(desc).c_str()); \
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

#define CHECKSIZE(arg0, arg1) \
    do { \
        if ((arg0) > (arg1)) { \
            MMI_HILOGE("arg0 value is out of arg1 size"); \
            return false; \
        } \
    } while (0)

#define CHKPS(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("CHKPS(%{public}s) is null", #cond); \
            return ""; \
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

#define CHKFR(cond, r, desc) \
    do { \
        if (!(cond)) { \
            MMI_HILOGE("CHKFR(%{public}s) is false, hint is %{public}s", #cond, desc); \
            return r; \
        } \
    } while (0)

#define CHK_KEY_ITEM(keyItem) \
    do { \
        if (!(keyItem)) { \
            MMI_HILOGE("The keyItem is nullopt"); \
            return false; \
        } \
    } while (0)

#define CHKPRV(cond, msg) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("CHKPRV(%{public}s) is null, msg %{public}s", #cond, msg); \
            return; \
        } \
    } while (0)

#define CHKNOKRV(cond, msg) \
    do { \
        if ((cond) != RET_OK) { \
            MMI_HILOGE("CHKNOKRV(%{public}s) is not RET_OK, hint is %{public}s", #cond, msg); \
            return; \
        } \
    } while (0)

#define CHKFRV(cond, msg) \
    do { \
        if (!(cond)) { \
            MMI_HILOGE("CHKFRV(%{public}s) is null, hint is %{public}s", #cond, msg); \
            return; \
        } \
    } while (0)

#define CHKPP(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGE("CHKPP(%{public}s) is null, return value is null", #cond); \
            return nullptr; \
        } \
    } while (0)

#define CHKPO(cond) \
    do { \
        if ((cond) == nullptr) { \
            MMI_HILOGW("%{public}s, (%{public}d), CHKPO(%{public}s) is null, return object is null", \
                __FILE__, __LINE__, #cond); \
            return {}; \
        } \
    } while (0)

#define CK(cond, ec) \
    do { \
        if (!(cond)) { \
            MMI_HILOGE("CK(%{public}s), errCode:%{public}d", #cond, ec); \
        } \
    } while (0)

#define CHK_PID_AND_TID() \
    do { \
        MMI_HILOGD("pid:%{public}d threadId:%{public}" PRIu64, GetPid(), GetThisThreadId()); \
    } while (0)

#endif

#define DEFRET_1(data, value, ...) (value)
#define DEFRET(...) DEFRET_1(__VA_ARGS__, false)

#define WRITEBOOL(parcel, data, ...) \
    do { \
        if (!(parcel).WriteBool(data)) { \
            MMI_HILOGE("WriteBool "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEINT32(parcel, data, ...) \
    do { \
        if (!(parcel).WriteInt32(data)) { \
            MMI_HILOGE("WriteInt32 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEINT64(parcel, data, ...) \
    do { \
        if (!(parcel).WriteInt64(data)) { \
            MMI_HILOGE("WriteInt64 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEUINT8(parcel, data, ...) \
    do { \
        if (!(parcel).WriteUint8(data)) { \
            MMI_HILOGE("WriteUint8 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEUINT32(parcel, data, ...) \
    do { \
        if (!(parcel).WriteUint32(data)) { \
            MMI_HILOGE("WriteUint32 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEUINT64(parcel, data, ...) \
    do { \
        if (!(parcel).WriteUint64(data)) { \
            MMI_HILOGE("WriteUint64 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEDOUBLE(parcel, data, ...) \
    do { \
        if (!(parcel).WriteDouble(data)) { \
            MMI_HILOGE("WriteDouble "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEFLOAT(parcel, data, ...) \
    do { \
        if (!(parcel).WriteFloat(data)) { \
            MMI_HILOGE("WriteFloat "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITESTRING(parcel, data, ...) \
    do { \
        if (!(parcel).WriteString(data)) { \
            MMI_HILOGE("WriteString "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEBUFFER(parcel, data, length, ...) \
    do { \
        if (!(parcel).WriteBuffer((data), length)) { \
            MMI_HILOGE("WriteBuffer "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define WRITEREMOTEOBJECT(parcel, data, ...) \
    do { \
        if (!(parcel).WriteRemoteObject(data)) { \
            MMI_HILOGE("WriteRemoteObject "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READBOOL(parcel, data, ...) \
    do { \
        if (!(parcel).ReadBool(data)) { \
            MMI_HILOGE("ReadBool "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READINT32(parcel, data, ...) \
    do { \
        if (!(parcel).ReadInt32(data)) { \
            MMI_HILOGE("ReadInt32 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READINT64(parcel, data, ...) \
    do { \
        if (!(parcel).ReadInt64(data)) { \
            MMI_HILOGE("ReadInt64 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READUINT8(parcel, data, ...) \
    do { \
        if (!(parcel).ReadUint8(data)) { \
            MMI_HILOGE("ReadUint8 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READUINT32(parcel, data, ...) \
    do { \
        if (!(parcel).ReadUint32(data)) { \
            MMI_HILOGE("ReadUint32 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READUINT64(parcel, data, ...) \
    do { \
        if (!(parcel).ReadUint64(data)) { \
            MMI_HILOGE("ReadUint64 "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READDOUBLE(parcel, data, ...) \
    do { \
        if (!(parcel).ReadDouble(data)) { \
            MMI_HILOGE("ReadDouble "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READFLOAT(parcel, data, ...) \
    do { \
        if (!(parcel).ReadFloat(data)) { \
            MMI_HILOGE("ReadFloat "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)

#define READSTRING(parcel, data, ...) \
    do { \
        if (!(parcel).ReadString(data)) { \
            MMI_HILOGE("ReadString "#data" failed"); \
            return DEFRET(false, ##__VA_ARGS__); \
        } \
    } while (0)
} // namespace MMI
} // namespace OHOS
#endif // DEFINE_MULTIMODAL_H
