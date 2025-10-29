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


#include "product_name_definition_parser.h"

#include "util.h"

#include <cJSON.h>

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ProductNameDefinitionParser"

namespace OHOS {
namespace MMI {
namespace {
constexpr std::string_view productNameDefinitionConfigDir {
    "/etc/multimodalinput/product_name_definition_config.json" };
constexpr int32_t maxJsonArraySize { 100 };
} // namespace

ProductNameDefinitionParser& ProductNameDefinitionParser::GetInstance()
{
    static ProductNameDefinitionParser instance;
    return instance;
}

int32_t ProductNameDefinitionParser::Init()
{
    CALL_DEBUG_ENTER;
    static std::once_flag init_flag;
    static int32_t initRes = RET_ERR;
    std::call_once(init_flag, [this]() {
        initRes = InitializeImpl();
    });
    return initRes;
}

int32_t ProductNameDefinitionParser::InitializeImpl()
{
    CALL_INFO_TRACE;
    std::string jsonStr = ReadJsonFile(std::string(productNameDefinitionConfigDir));
    if (jsonStr.empty()) {
        MMI_HILOGE("Read productName failed");
        return RET_ERR;
    }
    JsonParser parser(jsonStr.c_str());
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Not valid object");
        return RET_ERR;
    }
    if (ParseProductNameMap(parser) != RET_OK) {
        MMI_HILOGE("ParseProductNameMap failed");
        return RET_ERR;
    }
    PrintProductNames();
    return RET_OK;
}

std::string ProductNameDefinitionParser::GetProductName(const std::string &key)
{
    if (Init() != RET_OK) {
        MMI_HILOGE("Init failed");
        return "";
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (productNames_.find(key) != productNames_.end()) {
        return productNames_[key];
    }
    MMI_HILOGW("No %{public}s matched.", key.c_str());
    return "";
}

int32_t ProductNameDefinitionParser::ParseProductNameMap(const JsonParser &jsonParser)
{
    if (!cJSON_IsObject(jsonParser.Get())) {
        MMI_HILOGE("The jsonParser is not object");
        return RET_ERR;
    }
    cJSON *productNameMapJson = cJSON_GetObjectItemCaseSensitive(jsonParser.Get(), "product_name_definition");

    if (!cJSON_IsArray(productNameMapJson)) {
        MMI_HILOGE("productNameMapJson is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(productNameMapJson);
    if (arraySize > maxJsonArraySize) {
        MMI_HILOGW("arraySize is too much, truncate it");
    }
    for (int32_t i = 0; i < std::min(arraySize, maxJsonArraySize); i++) {
        cJSON* productNameItemJson = cJSON_GetArrayItem(productNameMapJson, i);
        CHKPC(productNameItemJson);
        ProductNameDefinitionItem productNameItem;
        if (ParserProductNameItem(productNameItemJson, productNameItem) != RET_OK) {
            MMI_HILOGE("ParserProductNameItem failed");
            continue;
        }
        std::unique_lock<std::shared_mutex> lock(lock_);
        productNames_.insert({ productNameItem.productAlias, productNameItem.productName });
    }
    return RET_OK;
}

int32_t ProductNameDefinitionParser::ParserProductNameItem(const cJSON *json,
    ProductNameDefinitionItem &productNameItem)
{
    if (JsonParser::ParseString(json, "product_alias", productNameItem.productAlias) != RET_OK) {
        MMI_HILOGE("Parse product_alias failed");
        return RET_ERR;
    }
    if (JsonParser::ParseString(json, "product_name", productNameItem.productName) != RET_OK) {
        MMI_HILOGE("Parse product_name failed");
        return RET_ERR;
    }
    return RET_OK;
}

void ProductNameDefinitionParser::PrintProductNames()
{
    CALL_INFO_TRACE;
    std::shared_lock<std::shared_mutex> lock(lock_);
    for (const auto &productName: productNames_) {
        MMI_HILOGD("key:%{public}s -> value:%{public}s", productName.first.c_str(), productName.second.c_str());
    }
}

} // namespace MMI
} // namespace OHOS