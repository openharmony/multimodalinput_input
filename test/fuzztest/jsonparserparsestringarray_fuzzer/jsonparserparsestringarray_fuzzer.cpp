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
#include "jsonparserparsestringarray_fuzzer.h"

#include "cJSON.h"
#include "json_parser.h"

namespace OHOS {
namespace MMI {
const int MAX_STRING_LENGTH = 100;
const int DEFAULT_STRING_LENGTH = 50;

enum DataType {
    STRING_ARRAY = 0,
    MIXED_ARRAY = 1,
    NUMBER_VALUE = 2,
    STRING_VALUE = 3,
    BOOL_VALUE = 4,
    NULL_VALUE = 5
};

enum ElemType {
    STRING_ELEM = 0,
    NUMBER_ELEM = 1,
    BOOL_ELEM = 2,
    NULL_ELEM = 3
};

cJSON* CreateStringArray(FuzzedDataProvider &fdp)
{
    cJSON* array = cJSON_CreateArray();
    if (array == nullptr) {
        return nullptr;
    }

    int arraySize = fdp.ConsumeIntegralInRange<int>(0, 20);
    for (int i = 0; i < arraySize; i++) {
        std::string strElement = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
        cJSON* strItem = cJSON_CreateString(strElement.c_str());
        if (strItem != nullptr) {
            cJSON_AddItemToArray(array, strItem);
        }
    }
    return array;
}
cJSON* CreateMixedArray(FuzzedDataProvider &fdp)
{
    cJSON* array = cJSON_CreateArray();
    if (array == nullptr) {
        return nullptr;
    }

    int arraySize = fdp.ConsumeIntegralInRange<int>(1, 10);
    for (int i = 0; i < arraySize; i++) {
        int elemType = fdp.ConsumeIntegralInRange<int>(0, 3);
        cJSON* item = nullptr;
        switch (elemType) {
            case STRING_ELEM:
                item = cJSON_CreateString(fdp.ConsumeRandomLengthString(DEFAULT_STRING_LENGTH).c_str());
                break;
            case NUMBER_ELEM:
                item = cJSON_CreateNumber(fdp.ConsumeFloatingPoint<double>());
                break;
            case BOOL_ELEM:
                item = cJSON_CreateBool(fdp.ConsumeBool());
                break;
            case NULL_ELEM:
                item = cJSON_CreateNull();
                break;
            default: {
                break;
            }
        }
        if (item != nullptr) {
            cJSON_AddItemToArray(array, item);
        }
    }
    return array;
}

cJSON* CreateJsonValue(FuzzedDataProvider &fdp, int dataType, const std::string& key)
{
    cJSON* jsonObj = cJSON_CreateObject();
    if (jsonObj == nullptr) {
        return nullptr;
    }

    switch (dataType) {
        case STRING_ARRAY: {
            cJSON* array = CreateStringArray(fdp);
            if (array != nullptr) {
                cJSON_AddItemToObject(jsonObj, key.c_str(), array);
            }
            break;
        }
        case MIXED_ARRAY: {
            cJSON* array = CreateMixedArray(fdp);
            if (array != nullptr) {
                cJSON_AddItemToObject(jsonObj, key.c_str(), array);
            }
            break;
        }
        case NUMBER_VALUE: {
            double numValue = fdp.ConsumeFloatingPoint<double>();
            cJSON_AddNumberToObject(jsonObj, key.c_str(), numValue);
            break;
        }
        case STRING_VALUE: {
            std::string strValue = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
            cJSON_AddStringToObject(jsonObj, key.c_str(), strValue.c_str());
            break;
        }
        case BOOL_VALUE: {
            bool boolValue = fdp.ConsumeBool();
            cJSON_AddBoolToObject(jsonObj, key.c_str(), boolValue);
            break;
        }
        case NULL_VALUE: {
            cJSON_AddNullToObject(jsonObj, key.c_str());
            break;
        }
        default: {
            break;
        }
    }
    return jsonObj;
}

void JsonParserParseStringArrayFuzzTest(FuzzedDataProvider &fdp)
{
    std::string key = fdp.ConsumeRandomLengthString(DEFAULT_STRING_LENGTH);
    int dataType = fdp.ConsumeIntegralInRange<int>(0, 5);

    cJSON* jsonObj = CreateJsonValue(fdp, dataType, key);
    if (jsonObj == nullptr) {
        return;
    }

    std::vector<std::string> resultValue;
    int32_t maxSize = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_STRING_LENGTH);
    OHOS::MMI::JsonParser::ParseStringArray(jsonObj, key, resultValue, maxSize);
    cJSON_Delete(jsonObj);

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
    OHOS::MMI::JsonParserParseStringArrayFuzzTest(fdp);
    return 0;
}