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

 #ifndef PRODUCT_NAME_DEFINITION_PARSER_H
#define PRODUCT_NAME_DEFINITION_PARSER_H
 
#include <shared_mutex>
#include <string>
#include <map>
#include <vector>
 
#include "json_parser.h"
#include "cJSON.h"
 
namespace OHOS {
namespace MMI {
 
class ProductNameDefinitionParser {
public:
    ProductNameDefinitionParser(const ProductNameDefinitionParser&) = delete;
    ProductNameDefinitionParser& operator=(const ProductNameDefinitionParser&) = delete;
    static ProductNameDefinitionParser& GetInstance();
    int32_t Init();
    std::string GetProductName(const std::string &key);
    int32_t ParseProductNameMap(const JsonParser &jsonParser);
 
private:
    struct ProductNameDefinitionItem {
        std::string productAlias;
        std::string productName;
    };
 
private:
    ProductNameDefinitionParser() = default;
    ~ProductNameDefinitionParser() = default;
    void PrintProductNames();
    int32_t ParserProductNameItem(const cJSON *json, ProductNameDefinitionItem &productNameItem);
 
private:
    std::map<std::string, std::string> productNames_;
    std::shared_mutex lock_;
    std::atomic_bool isInitialized_ { false };
};
 
} // namespace MMI
} // namespace OHOS
#define PRODUCT_NAME_DEFINITION_PARSER OHOS::MMI::ProductNameDefinitionParser::GetInstance()
#endif // PRODUCT_NAME_DEFINITION_PARSER_H