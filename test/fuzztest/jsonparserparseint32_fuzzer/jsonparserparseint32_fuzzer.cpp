/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include "jsonparserparseint32_fuzzer.h"

#include "cJSON.h"
#include "json_parser.h"

namespace OHOS {
namespace MMI {
const int DEFAULT_STRING_LENGTH = 50;
const int MAX_STRING_LENGTH = 100;

enum DataType {
    INT32_VALUE = 0,
    FLOAT_VALUE = 1,
    STRING_TYPE = 2,
    BOOL_TYPE = 3,
    NULL_TYPE = 4,
    BOUNDARY_VALUE = 5
};

enum BoundaryChoice {
    MAX_INT32 = 0,
    MIN_INT32 = 1,
    OVER_MAX_INT32 = 2,
    UNDER_MIN_INT32 = 3
};

double CreateBoundaryValue(FuzzedDataProvider &fdp)
{
    int boundaryChoice = fdp.ConsumeIntegralInRange<int>(0, 4);
    switch (boundaryChoice) {
        case MAX_INT32:
            return static_cast<double>(std::numeric_limits<int32_t>::max());
        case MIN_INT32:
            return static_cast<double>(std::numeric_limits<int32_t>::min());
        case OVER_MAX_INT32:
            return static_cast<double>(std::numeric_limits<int32_t>::max()) + MAX_STRING_LENGTH;
        case UNDER_MIN_INT32:
            return static_cast<double>(std::numeric_limits<int32_t>::min()) - MAX_STRING_LENGTH;
        default:
            return fdp.ConsumeFloatingPoint<double>();
    }
}

void JsonParserParseInt32FuzzTest(FuzzedDataProvider &fdp)
{
    cJSON* json = cJSON_CreateNumber(0.0);
    if (json == nullptr) {
        return;
    }

    std::string key = fdp.ConsumeRandomLengthString(DEFAULT_STRING_LENGTH);

    int dataType = fdp.ConsumeIntegralInRange<int>(0, 5);

    switch (dataType) {
        case INT32_VALUE: {
            int32_t intValue = fdp.ConsumeIntegral<int32_t>();
            cJSON_AddNumberToObject(json, key.c_str(), static_cast<double>(intValue));
            break;
        }
        case FLOAT_VALUE: {
            double floatValue = fdp.ConsumeFloatingPoint<double>();
            cJSON_AddNumberToObject(json, key.c_str(), floatValue);
            break;
        }
        case STRING_TYPE: {
            std::string strValue = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
            cJSON_AddStringToObject(json, key.c_str(), strValue.c_str());
            break;
        }
        case BOOL_TYPE: {
            bool boolValue = fdp.ConsumeBool();
            cJSON_AddBoolToObject(json, key.c_str(), boolValue);
            break;
        }
        case NULL_TYPE: {
            cJSON_AddNullToObject(json, key.c_str());
            break;
        }
        case BOUNDARY_VALUE: {
            double boundaryValue = CreateBoundaryValue(fdp);
            cJSON_AddNumberToObject(json, key.c_str(), boundaryValue);
            break;
        }
        default: {
            break;
        }
    }

    int32_t resultValue = 0;
    OHOS::MMI::JsonParser::ParseInt32(json, key, resultValue);

    cJSON_Delete(json);

    return;
}

} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::MMI::JsonParserParseInt32FuzzTest(fdp);
    return 0;
}