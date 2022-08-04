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

#include "uuid.h"

#include <algorithm>
#include <climits>
#include <iomanip>
#include <iostream>

#include <sys/time.h>

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t UUID_TIME_LOW_FIRST_BYTE = 0;
constexpr int32_t UUID_TIME_LOW_SECOND_BYTE = 1;
constexpr int32_t UUID_TIME_LOW_THIRD_BYTE = 2;
constexpr int32_t UUID_TIME_LOW_FOURTH_BYTE = 3;
constexpr int32_t UUID_TIME_MID_FIRST_BYTE = 4;
constexpr int32_t UUID_TIME_MID_SECOND_BYTE = 5;
constexpr int32_t UUID_VERSION = 6;
constexpr int32_t UUID_TIME_HIGH = 7;
constexpr int32_t UUID_VARIANT = 8;
constexpr int32_t UUID_CLOCK_SEQ = 9;
constexpr int32_t UUID_NODE_FIRST_BYTE = 10;
constexpr int32_t UUID_NODE_THIRD_BYTE = 12;
constexpr int32_t UUID_NODE_FOURTH_BYTE = 13;
constexpr int32_t UUID_NODE_FIFTH_BYTE = 14;
constexpr int32_t UUID_NODE_SIXTH_BYTE = 15;

constexpr int32_t BASE_BIT_OPT_SIZE = 8;
constexpr int32_t BIT_OPT_TWO_BYTE = 2;
constexpr int32_t BIT_OPT_THREE_BYTE = 3;
constexpr int32_t BIT_OPT_FOUR_BYTE = 4;
constexpr int32_t BIT_OPT_FIVE_BYTE = 5;
constexpr int32_t BIT_OPT_SIX_BYTE = 6;
constexpr int32_t BIT_OPT_SEVEN_BYTE = 7;
} // namespace

Uuid::Uuid()
{
    struct timeval tv;
    struct timezone tz;
    struct tm randomTime;
    uint32_t randNum = 0;

    rand_r(&randNum);
    gettimeofday(&tv, &tz);
    localtime_r(&tv.tv_sec, &randomTime);

    unsigned long int tvUsec = 0;
    tvUsec = (unsigned long int)tv.tv_usec;

    uuid_[UUID_NODE_SIXTH_BYTE] =
        static_cast<uint8_t>(tvUsec & 0x00000000000000FF);
    uuid_[UUID_NODE_FIFTH_BYTE] =
        static_cast<uint8_t>((tvUsec & 0x000000000000FF00) >> BASE_BIT_OPT_SIZE);
    uuid_[UUID_NODE_FOURTH_BYTE] =
        static_cast<uint8_t>((tvUsec & 0x0000000000FF0000) >> BIT_OPT_TWO_BYTE * BASE_BIT_OPT_SIZE);
    uuid_[UUID_NODE_THIRD_BYTE] =
        static_cast<uint8_t>((tvUsec & 0x00000000FF000000) >> BIT_OPT_THREE_BYTE * BASE_BIT_OPT_SIZE);
    uuid_[UUID_NODE_FIRST_BYTE] =
        static_cast<uint8_t>((tvUsec & 0x000000FF00000000) >> BIT_OPT_FOUR_BYTE * BASE_BIT_OPT_SIZE);
    uuid_[UUID_CLOCK_SEQ] =
        static_cast<uint8_t>((tvUsec & 0x0000FF0000000000) >> BIT_OPT_FIVE_BYTE * BASE_BIT_OPT_SIZE);
    uuid_[UUID_VARIANT] =
        static_cast<uint8_t>((tvUsec & 0x00FF000000000000) >> BIT_OPT_SIX_BYTE * BASE_BIT_OPT_SIZE);
    uuid_[UUID_TIME_HIGH] =
        static_cast<uint8_t>((tvUsec & 0xFF00000000000000) >> BIT_OPT_SEVEN_BYTE * BASE_BIT_OPT_SIZE);
    // 4 - 6
    uuid_[UUID_VERSION] =
        static_cast<uint8_t>((static_cast<uint32_t>(randomTime.tm_sec) + randNum) & 0xFF);
    uuid_[UUID_TIME_MID_SECOND_BYTE] =
        static_cast<uint8_t>((static_cast<uint32_t>(randomTime.tm_min) + (randNum >> BASE_BIT_OPT_SIZE)) & 0xFF);
    uuid_[UUID_TIME_MID_FIRST_BYTE] = static_cast<uint8_t>((static_cast<uint32_t>(randomTime.tm_hour) +
                                      (randNum >> BIT_OPT_TWO_BYTE * BASE_BIT_OPT_SIZE)) & 0xFF);
    // 0 - 3
    uuid_[UUID_TIME_LOW_FOURTH_BYTE] = static_cast<uint8_t>((static_cast<uint32_t>(randomTime.tm_mday) +
                                       (randNum >> BIT_OPT_THREE_BYTE * BASE_BIT_OPT_SIZE)) & 0xFF);
    uuid_[UUID_TIME_LOW_THIRD_BYTE] =
        static_cast<uint8_t>(static_cast<uint32_t>(randomTime.tm_mon) & 0xFF);
    uuid_[UUID_TIME_LOW_SECOND_BYTE] =
        static_cast<uint8_t>(static_cast<uint32_t>(randomTime.tm_year) & 0xFF);
    uuid_[UUID_TIME_LOW_FIRST_BYTE] =
        static_cast<uint8_t>((static_cast<uint32_t>(randomTime.tm_year) & 0xFF00) >> BASE_BIT_OPT_SIZE);
}

char ConvertToHex(uint8_t c)
{
    if (c < 0xa) {
        return static_cast<char>(c + '0');
    } else if (c >= 0xa && c <= 0xf) {
        return static_cast<char>(c - 0xa + 'a');
    }

    return '0';
}

void Uuid::ConvertToStdString(std::string& s) const
{
    static constexpr int32_t uuidBufMaxSize = 37;
    char uuidBuf[uuidBufMaxSize + 1] = {0};
    int32_t writePos = 0;
    for (size_t i = 0; i < UUID128_BYTES_TYPE; i++) {
        const uint8_t c = uuid_[i];
        const uint8_t low4Bit = (c & 0xf);
        const uint8_t high4Bit = ((c >> 4) & 0xf);
        if (writePos <= uuidBufMaxSize) {
            uuidBuf[writePos++] = ConvertToHex(low4Bit);
            uuidBuf[writePos++] = ConvertToHex(high4Bit);
            if (i == 3 || i == 5 || i == 7 || i == 9) { // 3 5 7 9 uuid 按标准格式(8-4-4-4-12)分隔符
                uuidBuf[writePos++] = '-';
            }
        }
    }
    uuidBuf[uuidBufMaxSize - 1] = '\0';
    s = uuidBuf;
}
} // namespace MMI
} // namespace OHOS
