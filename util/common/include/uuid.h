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

#ifndef UUID_H
#define UUID_H

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

/**
 * @brief The OHOS subsystem.
 */
namespace OHOS {
namespace MMI {
/**
 * @brief This class provides service uuid.
 *
 * @since 1.0
 * @version 1.0
 */
class Uuid {
public:
    // 128 bits uuid length type
    constexpr static int32_t UUID128_BYTES_TYPE = 16;
    // 32 bits uuid length
    constexpr static int32_t UUID32_BYTES_TYPE = 4;
    // 16 bits uuid length
    constexpr static int32_t UUID16_BYTES_TYPE = 2;
    using UUID128Bit = std::array<uint8_t, UUID128_BYTES_TYPE>;

    constexpr static int32_t UUID_TIME_LOW_FIRST_BYTE = 0;
    constexpr static int32_t UUID_TIME_LOW_SECEND_BYTE = 1;
    constexpr static int32_t UUID_TIME_LOW_THIRD_BYTE = 2;
    constexpr static int32_t UUID_TIME_LOW_FOURTH_BYTE = 3;
    constexpr static int32_t UUID_TIME_MID_FIRST_BYTE = 4;
    constexpr static int32_t UUID_TIME_MID_SECEND_BYTE = 5;
    constexpr static int32_t UUID_VERSION = 6;
    constexpr static int32_t UUID_TIME_HIGH = 7;
    constexpr static int32_t UUID_VARIANT = 8;
    constexpr static int32_t UUID_CLOCK_SEQ = 9;
    constexpr static int32_t UUID_NODE_FIRST_BYTE = 10;
    constexpr static int32_t UUID_NODE_SECEND_BYTE = 11;
    constexpr static int32_t UUID_NODE_THIRD_BYTE = 12;
    constexpr static int32_t UUID_NODE_FOURTH_BYTE = 13;
    constexpr static int32_t UUID_NODE_FIFTH_BYTE = 14;
    constexpr static int32_t UUID_NODE_SIXTH_BYTE = 15;

    constexpr static int32_t BASE_BIT_OPT_SIZE = 8;
    constexpr static int32_t BIT_OPT_TWO_BYTE = 2;
    constexpr static int32_t BIT_OPT_THREE_BYTE = 3;
    constexpr static int32_t BIT_OPT_FOUR_BYTE = 4;
    constexpr static int32_t BIT_OPT_FIVE_BYTE = 5;
    constexpr static int32_t BIT_OPT_SIX_BYTE = 6;
    constexpr static int32_t BIT_OPT_SEVEN_BYTE = 7;

    constexpr static int32_t SIZE_STRING_TO_INT = 2;
    /**
     * @brief A constructor used to create an <b>UUID</b> instance.
     *
     * @since 1.0
     * @version 1.0
     */
    Uuid();

    /**
     * @brief A constructor used to create an <b>UUID</b> instance.
     *
     * @param other Other uuid to create an <b>UUID</b> instance.
     * @since 1.0
     * @version 1.0
     */
    Uuid(const Uuid& other) = default;

    /**
     * @brief The assignment constructor.
     *
     * @param other Other uuid object.
     * @return Returns the reference of Uuid.
     * @since 1.0
     * @version 1.0
     */
    Uuid& operator=(const Uuid& other) = default;

    /**
     * @brief A destructor used to delete the <b>UUID</b> instance.
     *
     * @since 1.0
     * @version 1.0
     */
    ~Uuid() = default;

    /**
     * @brief Convert uuid to uint8_t* with little endian.
     *
     * @param[in] value : The 128 bits value for a uuid.
     * @return Returns <b>true</b> if the operation is successful;
     *         returns <b>false</b> if the operation fails.
     * @since 1.0
     * @version 1.0
     */
    void ConvertToStdString(std::string& s) const;

protected:
    /**
     * @brief Constructor.
     */
    Uuid(const UUID128Bit uuid) : uuid_(uuid) {};

    // base uuid value
    std::array<uint8_t, UUID128_BYTES_TYPE> BASE_UUID = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
    };

    std::array<uint8_t, UUID128_BYTES_TYPE> uuid_ = BASE_UUID;
};
}  // namespace MMI
}  // namespace OHOS

#endif // UUID_H