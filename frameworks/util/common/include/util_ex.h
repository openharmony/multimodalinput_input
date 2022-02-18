/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <map>
#include <vector>
#include <string>
#include <time.h>
#include <type_traits>
#include "securec.h"
#include "struct_multimodal.h"
#include "define_multimodal.h"
#include "log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
    template<class ...Ts>
    int32_t mprintf(int32_t fd, const char* fmt, Ts... args)
    {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UtilEx" };
        if (fmt == nullptr) {
            return RET_ERR;
        }
        int32_t ret = 0;

        constexpr size_t bufSize = 1024 * 10;
        char buf[bufSize] = {};
        ret = snprintf_s(buf, bufSize, bufSize - 1, fmt, args...);
        if (ret < 0) {
            return ret;
        }

        if (fd < 0) {
            ret = printf("%s\n", buf);
        } else if (fd == 0) {
            MMI_LOGF("%{public}s", buf);
        } else {
            ret = dprintf(fd, "%s\n", buf);
        }
        return ret;
    }

    template<class ...Ts>
    void DumpData(const char* dataPtr, const size_t dataSize, const char* fileName, const int lineNo,
        const char* titleFormat, Ts... args)
    {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UtilEx" };

        constexpr size_t outBufSize = 1024;
        char outBuf[outBufSize] = {};
        int writeLen = 0;
        int ret;
        auto funcAdvanceWriteLen = [&writeLen, ret]() {
            if (ret > 0) {
                writeLen += ret;
            }
        };

        auto funcOutput = [&writeLen, &ret, &outBuf, outBufSize]() {
            (void)memset_s(&outBuf[0], sizeof(outBuf), 0, sizeof(outBuf));
            writeLen = 0;
            ret = 0;
        };

        ret = sprintf_s(outBuf, outBufSize - writeLen, "[%s]", OHOS::MMI::GetProgramName());
        funcAdvanceWriteLen(ret);
        ret = sprintf_s(outBuf, outBufSize - writeLen, titleFormat, args...);
        funcAdvanceWriteLen(ret);
        ret = sprintf_s(outBuf, outBufSize - writeLen, " data size = %zu. %s:%d\n", dataSize, fileName, lineNo);
        funcAdvanceWriteLen(ret);

        funcOutput();

        constexpr size_t bufSize = 81;
        constexpr size_t oneLineCharCount = 16;
        constexpr size_t countStep = 2;
        constexpr size_t byteSize = 8;
        constexpr size_t wordSize = 16;
        char bufLeft[bufSize] = {};
        char bufRight[bufSize] = {};
        size_t writePosHex = 0;
        size_t writePosChar = 0;
        constexpr size_t writePosHexStep1 = 2;
        constexpr size_t writePosHexStep2 = 3;
        size_t i = 0;
        auto funCheckRetAndLog = [ret](const char* fileName, const int lineNo) -> void {
            if (ret == -1) {
                MMI_LOGE("SEC_RET_EQ: ret:%{public}d, %s:%d", ret, fileName, lineNo);
            }
        };

        for (i = 0; i < dataSize; ++i) {
            const unsigned char c = static_cast<unsigned char>(dataPtr[i]);
            ret = sprintf_s(bufLeft + writePosHex, bufSize - writePosHex, "%02x ", c);
            funCheckRetAndLog(MMI_LINE_INFO);
            if (i != 0 && (i + 1) % byteSize == 0 && (i + 1) % wordSize != 0) {
                ret = sprintf_s(bufLeft + writePosHex, bufSize - writePosHex, "- ");
                funCheckRetAndLog(MMI_LINE_INFO);
                writePosHex += writePosHexStep1;
            } else {
                writePosHex += writePosHexStep2;
            }
            if (isprint(c)) {
                ret = sprintf_s(bufRight + writePosChar, bufSize - writePosChar, "%c", c);
                funCheckRetAndLog(MMI_LINE_INFO);
                writePosChar += 1;
            } else {
                ret = sprintf_s(bufRight + writePosChar, bufSize - writePosChar, "%c", ' ');
                funCheckRetAndLog(MMI_LINE_INFO);
                writePosChar += 1;
            }
            if ((i != 0) && ((i + 1) % oneLineCharCount == 0)) {
                ret = sprintf_s(outBuf, outBufSize - writeLen, "%04zu-%04zu %s  %s\n",
                                i - (oneLineCharCount - 1), i, bufLeft, bufRight);
                funcAdvanceWriteLen(ret);
                funcOutput();
                (void)memset_s(bufLeft, sizeof(bufLeft), 0, sizeof(bufLeft));
                (void)memset_s(bufRight, sizeof(bufRight), 0, sizeof(bufRight));
                writePosHex = 0;
                writePosChar = 0;
            }
        }

        if (writePosHex != 0) {
            size_t ibefore = 0;
            if (i > (oneLineCharCount - 1)) {
                i = ((i + (oneLineCharCount - countStep)) % (oneLineCharCount - 1)) - (oneLineCharCount - 1);
            }
            size_t iafter = ((i + (oneLineCharCount - 2)) % (oneLineCharCount - 1));
            ret = sprintf_s(outBuf, outBufSize - writeLen, "%04zu-%04zu %s  %s\n", ibefore, iafter, bufLeft, bufRight);
                            funcAdvanceWriteLen(ret);
            funcOutput();
        }
    }

    template <class Enum>
    constexpr auto EnumUnderlyingValue(Enum const e) -> typename std::underlying_type<Enum>::type
    {
        static_assert(std::is_enum<Enum>::value, "input value is not of enum class nor enum");
        return static_cast<typename std::underlying_type<Enum>::type>(e);
    }

    template <class Enum, class T>
    Enum EnumAdd(Enum const e, T val)
    {
        static_assert(std::is_enum<Enum>::value, "input value is not of enum class nor enum");
        auto a = EnumUnderlyingValue(e);
        return static_cast<Enum>(a + val);
    }
} // namespace MMI
} // namespace OHOS

#endif // UTIL_EX_H