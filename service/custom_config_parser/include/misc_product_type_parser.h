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

 
#ifndef MISC_PRODUCT_TYPE_PARSER_H
#define MISC_PRODUCT_TYPE_PARSER_H
 
#include <shared_mutex>
#include <string>
#include <map>
#include <vector>
 
#include "json_parser.h"
#include "cJSON.h"
 
namespace OHOS {
namespace MMI {
 
class MiscProductTypeParser {
public:
    MiscProductTypeParser(const MiscProductTypeParser&) = delete;
    MiscProductTypeParser& operator=(const MiscProductTypeParser&) = delete;
    static MiscProductTypeParser& GetInstance();
    int32_t Init();
    int32_t GetFlipVolumeSupportedProduct(std::vector<std::string> &productList);
    int32_t GetSensorSaListenerProduct(std::vector<std::string> &productList);
 
private:
    MiscProductTypeParser() = default;
    ~MiscProductTypeParser() = default;
    int32_t ParseFlipVolumeSupportedProduct(const JsonParser &jsonParser);
    int32_t ParseSensorSaListenerProduct(const JsonParser &jsonParser);
    inline int32_t InsertToMiscProductTypes(const std::string &key, const std::vector<std::string> &value);
    void PrintMiscProductTypes();
 
private:
    std::map<std::string, std::vector<std::string>> miscProductTypes_;
    std::shared_mutex lock_;
    std::atomic_bool isInitialized_ { false };
};
} // namespace MMI
} // namespace OHOS
#define MISC_PRODUCT_TYPE_PARSER OHOS::MMI::MiscProductTypeParser::GetInstance()
#endif // MISC_PRODUCT_TYPE_PARSER_H