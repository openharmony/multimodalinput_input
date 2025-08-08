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

 #ifndef PRODUCT_TYPE_PARSER_H
#define PRODUCT_TYPE_PARSER_H
 
#include <shared_mutex>
#include <string>
#include <map>
 
#include "device_type_definition.h"
#include "json_parser.h"
#include "cJSON.h"
 
namespace OHOS {
namespace MMI {
 
class ProductTypeParser {
public:
    ProductTypeParser(const ProductTypeParser&) = delete;
    ProductTypeParser& operator=(const ProductTypeParser&) = delete;
    static ProductTypeParser& GetInstance();
    int32_t Init();
    int32_t GetProductType(const std::string &productName, DeviceType &deviceType);
 
private:
    ProductTypeParser() = default;
    ~ProductTypeParser() = default;
 
private:
    struct ProductNameType {
        std::string productName;
        std::string productType;
    };
 
    int32_t ParseProductnameTypeItem(const cJSON *json, ProductNameType &productNameType);
    inline int32_t InsertProductType(const ProductNameType &productNameType);
    void PrintProductType();
 
private:
    std::map<std::string, std::string> productTypes_;
    std::shared_mutex lock_;
    std::atomic_bool isInitialized_ { false };
};
} // namespace MMI
} // namespace OHOS
#define PRODUCT_TYPE_PARSER OHOS::MMI::ProductTypeParser::GetInstance()
#endif // PRODUCT_TYPE_PARSER_H
未读
service/custom_config_parser/include/special_input_device_parser.h
770
0 → 100644