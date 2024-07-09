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
 
#ifndef MMI_LOG_H
#define MMI_LOG_H

#include <cinttypes>
#include <functional>
#include <future>
#include <string>
#include <sstream>

#include "hilog/log.h"

#include "util.h"
#include "klog.h"

#ifndef MMI_DISABLE_LOG_TRACE

namespace OHOS {
namespace MMI {
class LogTracer {
public:
    LogTracer();

    LogTracer(int64_t, int32_t, int32_t);

    LogTracer(LogTracer &&other) noexcept;

    LogTracer &operator=(LogTracer &&other) noexcept;

    ~LogTracer();

private:
    int64_t traceId_;
};

void StartLogTraceId(int64_t, int32_t, int32_t);

void EndLogTraceId(int64_t);

const char *FormatLogTrace();

void ResetLogTrace();
}
}

#define MMI_FUNC_FMT "[%{public}s][%{public}s:%{public}d] "
#define MMI_FUNC_NOLINE_FMT "[%{public}s][%{public}s] "
#define INPUT_KEY_FLOW "InputKeyFlow"
#define MMI_TRACE_ID  (OHOS::MMI::FormatLogTrace()),
#else
#define MMI_FUNC_FMT "[%{public}s:%{public}d] "
#define MMI_FUNC_NOLINE_FMT "[%{public}s] "
#define MMI_TRACE_ID
#endif //MMI_DISABLE_LOG_TRACE

#ifdef MMI_LOG_DOMAIN
#undef MMI_LOG_DOMAIN
#endif
#ifdef MMI_LOG_FRAMEWORK
#undef MMI_LOG_FRAMEWORK
#endif
#define MMI_LOG_FRAMEWORK 0XD002800
#ifdef MMI_LOG_SERVER
#undef MMI_LOG_SERVER
#endif
#define MMI_LOG_SERVER 0XD002801
#ifdef MMI_LOG_HANDLER
#undef MMI_LOG_HANDLER
#endif
#define MMI_LOG_HANDLER 0XD002802
#ifdef MMI_LOG_WINDOW
#undef MMI_LOG_WINDOW
#endif
#define MMI_LOG_WINDOW 0XD002803
#ifdef MMI_LOG_CURSOR
#undef MMI_LOG_CURSOR
#endif
#define MMI_LOG_CURSOR 0XD002804
#ifdef MMI_LOG_DISPATCH
#undef MMI_LOG_DISPATCH
#endif
#define MMI_LOG_DISPATCH 0XD002805
#ifdef MMI_LOG_ANRDETECT
#undef MMI_LOG_ANRDETECT
#endif
#define MMI_LOG_ANRDETECT 0XD002806

#define MMI_LOG_DOMAIN MMI_LOG_FRAMEWORK

#ifndef MMI_FUNC_INFO
#define MMI_FUNC_INFO __FUNCTION__
#endif

#ifndef MMI_FILE_NAME
#define MMI_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif

#ifndef MMI_LINE_INFO
#define MMI_LINE_INFO   MMI_FILE_NAME, __LINE__
#endif

#define MMI_HILOG_BASE(type, level, domain, tag, fmt, ...) do { \
        HILOG_IMPL(type, level, domain, tag, MMI_FUNC_FMT fmt, MMI_TRACE_ID MMI_FUNC_INFO, __LINE__, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_HEADER(level, lh, fmt, ...) do { \
        HILOG_IMPL(LOG_CORE, level, lh.domain, lh.tag, MMI_FUNC_FMT fmt, MMI_TRACE_ID lh.func, lh.line, \
        ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_HEADER_NO_RELEASE(level, lh, fmt, ...) do { \
        HILOG_IMPL(LOG_ONLY_PRERELEASE, level, lh.domain, lh.tag, MMI_FUNC_FMT fmt, MMI_TRACE_ID lh.func, lh.line, \
        ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_CORE, LOG_DEBUG, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOGD_NO_RELEASE(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_DEBUG, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

#define MMI_HILOGI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOGI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGW(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_WARN, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOGW_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_WARN, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOGE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGF(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_FATAL, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOGF_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_FATAL, MMI_LOG_DOMAIN, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_SERVERD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_SERVER, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_CORE, LOG_DEBUG, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOG_SERVERD_NO_RELEASE(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_SERVER, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_DEBUG, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

#define MMI_HILOG_SERVERI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_SERVERI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_SERVERW(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_WARN, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_SERVERW_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_WARN, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_SERVERE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_SERVERE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_SERVERF(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_FATAL, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_SERVERF_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_FATAL, MMI_LOG_SERVER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_HANDLERD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_HANDLER, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_CORE, LOG_DEBUG, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOG_HANDLERD_NO_RELEASE(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_HANDLER, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_DEBUG, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

#define MMI_HILOG_HANDLERI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_HANDLERI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_HANDLERW(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_WARN, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_HANDLERW_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_WARN, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_HANDLERE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_HANDLERE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_HANDLERF(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_FATAL, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_HANDLERF_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_FATAL, MMI_LOG_HANDLER, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_WINDOWD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_WINDOW, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_CORE, LOG_DEBUG, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOG_WINDOWD_NO_RELEASE(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_WINDOW, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_DEBUG, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

#define MMI_HILOG_WINDOWI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_WINDOWI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_WINDOWW(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_WARN, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_WINDOWW_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_WARN, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_WINDOWE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_WINDOWE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_WINDOWF(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_FATAL, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_WINDOWF_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_FATAL, MMI_LOG_WINDOW, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_CURSORD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_CURSOR, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_CORE, LOG_DEBUG, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOG_CURSORD_NO_RELEASE(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_CURSOR, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_DEBUG, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

#define MMI_HILOG_CURSORI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_CURSORI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_CURSORW(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_WARN, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_CURSORW_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_WARN, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_CURSORE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_CURSORE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_CURSORF(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_FATAL, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_CURSORF_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_FATAL, MMI_LOG_CURSOR, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_DISPATCHD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_DISPATCH, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_CORE, LOG_DEBUG, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOG_DISPATCHD_NO_RELEASE(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_DISPATCH, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_DEBUG, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

#define MMI_HILOG_DISPATCHI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_DISPATCHI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_DISPATCHW(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_WARN, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_DISPATCHW_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_WARN, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_DISPATCHE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_DISPATCHE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_DISPATCHF(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_FATAL, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_DISPATCHF_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_FATAL, MMI_LOG_DISPATCH, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_FREEZEI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_DISPATCH, INPUT_KEY_FLOW, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_FREEZEI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_DISPATCH, INPUT_KEY_FLOW, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_FREEZEE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_DISPATCH, INPUT_KEY_FLOW, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_FREEZEE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_DISPATCH, INPUT_KEY_FLOW, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_ANRDETECTD(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_DISPATCH, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_CORE, LOG_DEBUG, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)
#define MMI_HILOG_ANRDETECTD_NO_RELEASE(fmt, ...) do { \
    if (HiLogIsLoggable(MMI_LOG_DISPATCH, MMI_LOG_TAG, LOG_DEBUG)) { \
        MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_DEBUG, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
    } \
} while (0)

#define MMI_HILOG_ANRDETECTI(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_INFO, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_ANRDETECTI_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_INFO, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_ANRDETECTW(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_WARN, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_ANRDETECTW_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_WARN, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_ANRDETECTE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_ERROR, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_ANRDETECTE_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_ERROR, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOG_ANRDETECTF(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_CORE, LOG_FATAL, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)
#define MMI_HILOG_ANRDETECTF_NO_RELEASE(fmt, ...) do { \
    MMI_HILOG_BASE(LOG_ONLY_PRERELEASE, LOG_FATAL, MMI_LOG_ANRDETECT, MMI_LOG_TAG, fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGDK(fmt, ...) do { \
    KMSG_LOGD(fmt, ##__VA_ARGS__); \
    MMI_HILOGD(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGIK(fmt, ...) do { \
    KMSG_LOGI(fmt, ##__VA_ARGS__); \
    MMI_HILOGI(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGWK(fmt, ...) do { \
    KMSG_LOGW(fmt, ##__VA_ARGS__); \
    MMI_HILOGW(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGEK(fmt, ...) do { \
    KMSG_LOGE(fmt, ##__VA_ARGS__); \
    MMI_HILOGE(fmt, ##__VA_ARGS__); \
} while (0)

#define MMI_HILOGFK(fmt, ...) do { \
    KMSG_LOGF(fmt, ##__VA_ARGS__); \
    MMI_HILOGF(fmt, ##__VA_ARGS__); \
} while (0)

namespace OHOS {
namespace MMI {
inline constexpr int32_t EVENT_TYPE_POINTER { 0X00020000 };
inline constexpr int32_t TIMEOUT { 100000 };
inline constexpr int32_t POINTER_ACTION_UP { 4 };
inline constexpr int32_t POINTER_ACTION_MOVE { 3 };
inline constexpr int32_t FINAL_FINGER { 1 };

class InnerFunctionTracer {
public:
    InnerFunctionTracer(LogLevel level, const char* tag, const char* logfn, uint32_t logline)
        : level_ { level }, tag_ { tag }, logfn_ { logfn }, logline_ { logline }
    {
        if (HiLogIsLoggable(MMI_LOG_DOMAIN, tag_, level_)) {
            if (logfn_ != nullptr) {
                HILOG_IMPL(LOG_CORE, level_, MMI_LOG_DOMAIN, tag_, MMI_FUNC_FMT "enter", MMI_TRACE_ID logfn_, logline_);
            }
        }
    }
    ~InnerFunctionTracer()
    {
        if (HiLogIsLoggable(MMI_LOG_DOMAIN, tag_, level_)) {
            if (logfn_ != nullptr) {
                HILOG_IMPL(LOG_CORE, level_, MMI_LOG_DOMAIN, tag_, MMI_FUNC_NOLINE_FMT "leave", MMI_TRACE_ID logfn_);
            }
        }
    }
private:
    LogLevel level_ { LOG_LEVEL_MIN };
    const char* tag_ { nullptr };
    const char* logfn_ { nullptr };
    const uint32_t logline_ { 0 };
};

struct LogHeader {
    const uint32_t domain;
    const char* tag;
    const char* func;
    const uint32_t line;

    LogHeader(uint32_t domain, const char* tag, const char* func, uint32_t line)
        : domain(domain), tag(tag), func(func), line(line) {}
};
} // namespace MMI
} // namespace OHOS

#define MMI_LOG_HEADER { MMI_LOG_DOMAIN, MMI_LOG_TAG, __FUNCTION__, __LINE__ }
#define MMI_LOG_FREEZE { MMI_LOG_DOMAIN, INPUT_KEY_FLOW, __FUNCTION__, __LINE__ }

#define CALL_DEBUG_ENTER ::OHOS::MMI::InnerFunctionTracer __innerFuncTracer_Debug___ \
    { LOG_DEBUG, MMI_LOG_TAG, __FUNCTION__, __LINE__ }
#define CALL_INFO_TRACE ::OHOS::MMI::InnerFunctionTracer ___innerFuncTracer_Info___ \
    { LOG_INFO, MMI_LOG_TAG, __FUNCTION__, __LINE__  }
#define CALL_TEST_DEBUG ::OHOS::MMI::InnerFunctionTracer ___innerFuncTracer_Info___ \
    { LOG_DEBUG, MMI_LOG_TAG, test_info_ == nullptr ? "TestBody" : test_info_->name(), __LINE__ }
#endif // MMI_LOG_H
