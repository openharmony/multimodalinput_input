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
#include "jsonparserparsestring_fuzzer.h"

#include "cJSON.h"
#include "json_parser.h"

namespace OHOS {
namespace MMI {
const int MAX_STRING_LENGTH = 1000;
const int DEFAULT_STRING_LENGTH = 50;
enum DataType {
    STRING_VALUE = 0,
    NUMBER_VALUE = 1,
    BOOL_VALUE = 2,
    NULL_VALUE = 3,
    STRING_ARRAY = 4
};

void JsonParserParseStringFuzzTest(FuzzedDataProvider &fdp)
{
    cJSON* json = cJSON_CreateNumber(0.0);
    if (json == nullptr) {
        return;
    }

    std::string key = fdp.ConsumeRandomLengthString(DEFAULT_STRING_LENGTH);

    int dataType = fdp.ConsumeIntegralInRange<int>(0, 4);

    switch (dataType) {
        case STRING_VALUE: {
            std::string strValue = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
            cJSON_AddStringToObject(json, key.c_str(), strValue.c_str());
            break;
        }
        case NUMBER_VALUE: {
            double numValue = fdp.ConsumeFloatingPoint<double>();
            cJSON_AddNumberToObject(json, key.c_str(), numValue);
            break;
        }
        case BOOL_VALUE: {
            bool boolValue = fdp.ConsumeBool();
            cJSON_AddBoolToObject(json, key.c_str(), boolValue);
            break;
        }
        case NULL_VALUE: {
            cJSON_AddNullToObject(json, key.c_str());
            break;
        }
        case STRING_ARRAY: {
            cJSON* array = cJSON_CreateArray();
            if (array != nullptr) {
                cJSON_AddItemToObject(json, key.c_str(), array);
            }
            break;
        }
        default: {
            break;
        }
    }

    std::string resultValue;
    OHOS::MMI::JsonParser::ParseString(json, key, resultValue);

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
    OHOS::MMI::JsonParserParseStringFuzzTest(fdp);
    return 0;
}