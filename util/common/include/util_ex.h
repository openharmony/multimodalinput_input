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

    static constexpr size_t BUF_SIZE = 1024 * 10;
    char buf[BUF_SIZE] = {};
    int32_t ret = snprintf_s(buf, BUF_SIZE, BUF_SIZE - 1, fmt, args...);
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

template<class ...Ts>
void DumpData(const char* dataPtr, const size_t dataSize, const char* fileName, const int32_t lineNo,
    const char* titleFormat, Ts... args)
{
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UtilEx" };

    constexpr size_t OUT_BUF_SIZE = 1024;
    char outBuf[OUT_BUF_SIZE] = {};
    int32_t writeLen = 0;
    int32_t ret;
    auto funcAdvanceWriteLen = [&writeLen, ret]() {
        if (ret > 0) {
            writeLen += ret;
        }
    };

    auto funcOutput = [&writeLen, &ret, &outBuf, OUT_BUF_SIZE]() {
        (void)memset_s(&outBuf[0], sizeof(outBuf), 0, sizeof(outBuf));
        writeLen = 0;
        ret = 0;
    };

    ret = sprintf_s(outBuf, OUT_BUF_SIZE - writeLen, "[%s]", GetProgramName());
    funcAdvanceWriteLen(ret);
    ret = sprintf_s(outBuf, OUT_BUF_SIZE - writeLen, titleFormat, args...);
    funcAdvanceWriteLen(ret);
    ret = sprintf_s(outBuf, OUT_BUF_SIZE - writeLen, " data size = %zu. %s:%d\n", dataSize, fileName, lineNo);
    funcAdvanceWriteLen(ret);

    funcOutput();

    static constexpr size_t BUF_SIZE = 81;
    static constexpr size_t ONE_LINE_CHAR_COUNT = 16;
    static constexpr size_t COUNT_STEP = 2;
    static constexpr size_t BYTE_SIZE = 8;
    static constexpr size_t WORD_SIZE = 16;
    char bufLeft[BUF_SIZE] = {};
    char bufRight[BUF_SIZE] = {};
    size_t writePosHex = 0;
    size_t writePosChar = 0;
    static constexpr size_t WRITE_POS_HEX_STEP1 = 2;
    static constexpr size_t WRITE_POS_HEX_STEP2 = 3;
    size_t i = 0;
    auto funCheckRetAndLog = [ret](const char* fileName, const int32_t lineNo) -> void {
        if (ret == -1) {
            MMI_HILOGE("SEC_RET_EQ: ret:%{public}d, %s:%d", ret, fileName, lineNo);
        }
    };

    for (i = 0; i < dataSize; i++) {
        const unsigned char c = static_cast<unsigned char>(dataPtr[i]);
        ret = sprintf_s(bufLeft + writePosHex, BUF_SIZE - writePosHex, "%02x ", c);
        funCheckRetAndLog(MMI_LINE_INFO);
        if (i != 0 && (i + 1) % BYTE_SIZE == 0 && (i + 1) % WORD_SIZE != 0) {
            ret = sprintf_s(bufLeft + writePosHex, BUF_SIZE - writePosHex, "- ");
            funCheckRetAndLog(MMI_LINE_INFO);
            writePosHex += WRITE_POS_HEX_STEP1;
        } else {
            writePosHex += WRITE_POS_HEX_STEP2;
        }
        if (isprint(c)) {
            ret = sprintf_s(bufRight + writePosChar, BUF_SIZE - writePosChar, "%c", c);
            funCheckRetAndLog(MMI_LINE_INFO);
            writePosChar += 1;
        } else {
            ret = sprintf_s(bufRight + writePosChar, BUF_SIZE - writePosChar, "%c", ' ');
            funCheckRetAndLog(MMI_LINE_INFO);
            writePosChar += 1;
        }
        if ((i != 0) && ((i + 1) % ONE_LINE_CHAR_COUNT == 0)) {
            ret = sprintf_s(outBuf, OUT_BUF_SIZE - writeLen, "%04zu-%04zu %s  %s\n",
                            i - (ONE_LINE_CHAR_COUNT - 1), i, bufLeft, bufRight);
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
        if (i > (ONE_LINE_CHAR_COUNT - 1)) {
            i = ((i + (ONE_LINE_CHAR_COUNT - COUNT_STEP)) % (ONE_LINE_CHAR_COUNT - 1)) - (ONE_LINE_CHAR_COUNT - 1);
        }
        size_t iafter = ((i + (ONE_LINE_CHAR_COUNT - 2)) % (ONE_LINE_CHAR_COUNT - 1));
        ret = sprintf_s(outBuf, OUT_BUF_SIZE - writeLen, "%04zu-%04zu %s  %s\n", ibefore, iafter, bufLeft, bufRight);
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