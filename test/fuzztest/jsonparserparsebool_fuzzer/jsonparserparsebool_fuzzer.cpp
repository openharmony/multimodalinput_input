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
#include "jsonparserparsebool_fuzzer.h"

#include "cJSON.h"
#include "json_parser.h"

namespace OHOS {
namespace MMI {
const int DEFAULT_STRING_LENGTH = 50;
const int MAX_STRING_LENGTH = 100;

enum DataType {
    BOOL_TRUE = 0,
    BOOL_FALSE = 1,
    NUMBER_TYPE = 2,
    STRING_TYPE = 3,
    NULL_TYPE = 4,
    ARRAY_TYPE = 5
};

void JsonParserParseBoolFuzzTest(FuzzedDataProvider &fdp)
{
    cJSON* json = cJSON_CreateObject();
    if (json == nullptr) {
        return;
    }

    std::string key = fdp.ConsumeRandomLengthString(DEFAULT_STRING_LENGTH);

    int dataType = fdp.ConsumeIntegralInRange<int>(0, 5);

    switch (dataType) {
        case BOOL_TRUE: {
            cJSON_AddBoolToObject(json, key.c_str(), 1);
            break;
        }
        case BOOL_FALSE: {
            cJSON_AddBoolToObject(json, key.c_str(), 0);
            break;
        }
        case NUMBER_TYPE: {
            double numValue = fdp.ConsumeFloatingPoint<double>();
            cJSON_AddNumberToObject(json, key.c_str(), numValue);
            break;
        }
        case STRING_TYPE: {
            std::string strValue = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
            cJSON_AddStringToObject(json, key.c_str(), strValue.c_str());
            break;
        }
        case NULL_TYPE: {
            cJSON_AddNullToObject(json, key.c_str());
            break;
        }
        case ARRAY_TYPE: {
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

    bool resultValue = false;
    OHOS::MMI::JsonParser::ParseBool(json, key, resultValue);

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
    OHOS::MMI::JsonParserParseBoolFuzzTest(fdp);
    return 0;
}