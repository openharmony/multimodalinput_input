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


#include "product_type_parser.h"

#include "define_multimodal.h"

#include "json_parser.h"
#include "util.h"

#include <cJSON.h>

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ProductTypeParser"

namespace OHOS {
namespace MMI {
namespace {
constexpr std::string_view productTypeDir {
    "/etc/multimodalinput/product_name_2_type_config.json" };
constexpr int32_t maxJsonArraySize { 100 };
} // namespace

ProductTypeParser& ProductTypeParser::GetInstance()
{
    static ProductTypeParser instance;
    return instance;
}

int32_t ProductTypeParser::Init()
{
    CALL_DEBUG_ENTER;
    static std::once_flag init_flag;
    static int32_t initRes = RET_ERR;
    std::call_once(init_flag, [this]() {
        initRes = InitializeImpl();
    });
    return initRes;
}

int32_t ProductTypeParser::InitializeImpl()
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(std::string(productTypeDir));
    if (jsonStr.empty()) {
        MMI_HILOGE("Read productType failed");
        return RET_ERR;
    }
    JsonParser parser(jsonStr.c_str());
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Not valid object");
        return RET_ERR;
    }

    cJSON *productNameTypesJson = cJSON_GetObjectItemCaseSensitive(parser.Get(), "product_name_types");
    if (!cJSON_IsArray(productNameTypesJson)) {
        MMI_HILOGE("product_name_types is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(productNameTypesJson);
    if (arraySize > maxJsonArraySize) {
        MMI_HILOGW("arraySize is too much, truncate it");
    }
    for (int32_t i = 0; i < std::min(arraySize, maxJsonArraySize); i++) {
        cJSON* productNameTypeItemJson = cJSON_GetArrayItem(productNameTypesJson, i);
        if (productNameTypeItemJson == nullptr) {
            MMI_HILOGE("The productNameTypeItem init failed");
            continue;
        }
        ProductTypeParser::ProductNameType productNameType;
        if (ParseProductnameTypeItem(productNameTypeItemJson, productNameType) != RET_OK) {
            MMI_HILOGE("ParseProductnameTypeItem failed");
            continue;
        }
        InsertProductType(productNameType);
    }
    PrintProductType();
    return RET_OK;
}

int32_t ProductTypeParser::GetProductType(const std::string &productName, DeviceType &deviceType)
{
    if (Init() != RET_OK) {
        MMI_HILOGE("Init failed");
        return RET_ERR;
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (productTypes_.find(productName) != productTypes_.end()) {
        if (gDeviceTypeMap.find(productTypes_[productName]) != gDeviceTypeMap.end()) {
            deviceType = gDeviceTypeMap.at(productTypes_[productName]);
            return RET_OK;
        }
    }
    return RET_ERR;
}

int32_t ProductTypeParser::ParseProductnameTypeItem(const cJSON *json, ProductNameType &productNameType)
{
    if (JsonParser::ParseString(json, "product_name", productNameType.productName) != RET_OK) {
        MMI_HILOGE("Parse product_name failed");
        return RET_ERR;
    }
    if (JsonParser::ParseString(json, "product_type", productNameType.productType) != RET_OK) {
        MMI_HILOGE("Parse product_type failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ProductTypeParser::InsertProductType(const ProductNameType &productNameType)
{
    std::unique_lock<std::shared_mutex> lock(lock_);
    productTypes_.insert({productNameType.productName, productNameType.productType});
    return RET_OK;
}

void ProductTypeParser::PrintProductType()
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    for (const auto &elem : productTypes_) {
        MMI_HILOGI("productName:%{public}s -> productType:%{public}s", elem.first.c_str(), elem.second.c_str());
    }
}
} // namespace MMI
} // namespace OHOS