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

 
#include "misc_product_type_parser.h"

#include "json_parser.h"
#include "util.h"

#include <cJSON.h>

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MiscProductTypeParser"

namespace OHOS {
namespace MMI {
namespace {
constexpr std::string_view miscProductTypeDir { "/etc/multimodalinput/misc_product_type_config.json" };
constexpr int32_t maxJsonArraySize { 100 };
}

MiscProductTypeParser& MiscProductTypeParser::GetInstance()
{
    static MiscProductTypeParser instance;
    return instance;
}

int32_t MiscProductTypeParser::Init()
{
    CALL_DEBUG_ENTER;
    static std::once_flag init_flag;
    static int32_t initRes = RET_ERR;
    std::call_once(init_flag, [this]() {
        initRes = InitializeImpl();
    });
    return initRes;
}

int32_t MiscProductTypeParser::InitializeImpl()
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(std::string(miscProductTypeDir));
    if (jsonStr.empty()) {
        MMI_HILOGE("Read miscProductType failed");
        return RET_ERR;
    }
    JsonParser parser(jsonStr.c_str());
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Not valid object");
        return RET_ERR;
    }
    if (ParseFlipVolumeSupportedProduct(parser) != RET_OK) {
        MMI_HILOGE("ParseFlipVolumeSupportedProduct failed");
        return RET_ERR;
    }
    if (ParseSensorSaListenerProduct(parser) != RET_OK) {
        MMI_HILOGE("ParseSensorSaListenerProduct failed");
        return RET_ERR;
    }
    PrintMiscProductTypes();
    return RET_OK;
}

int32_t MiscProductTypeParser::GetFlipVolumeSupportedProduct(std::vector<std::string> &productList)
{
    if (Init() != RET_OK) {
        MMI_HILOGE("Init failed");
        return RET_ERR;
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (miscProductTypes_.find("flip_volume_supported_product") != miscProductTypes_.end()) {
        productList =  miscProductTypes_["flip_volume_supported_product"];
        return RET_OK;
    }
    return RET_ERR;
}

int32_t MiscProductTypeParser::GetSensorSaListenerProduct(std::vector<std::string> &productList)
{
    Init();
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (miscProductTypes_.find("sensor_sa_listener_product") != miscProductTypes_.end()) {
        productList =  miscProductTypes_["sensor_sa_listener_product"];
        return RET_OK;
    }
    return RET_ERR;
}

int32_t MiscProductTypeParser::ParseFlipVolumeSupportedProduct(const JsonParser &jsonParser)
{
    std::vector<std::string> products;
    if (JsonParser::ParseStringArray(jsonParser.Get(), "flip_volume_supported_product", products, maxJsonArraySize)
        != RET_OK) {
        MMI_HILOGE("Parse flip_volume_supported_product failed");
        return RET_ERR;
    }
    InsertToMiscProductTypes("flip_volume_supported_product", products);
    return RET_OK;
}

int32_t MiscProductTypeParser::ParseSensorSaListenerProduct(const JsonParser &jsonParser)
{
    std::vector<std::string> products;
    if (JsonParser::ParseStringArray(jsonParser.Get(), "sensor_sa_listener_product", products, maxJsonArraySize)
        != RET_OK) {
        MMI_HILOGE("Parse sensor_sa_listener_product failed");
        return RET_ERR;
    }
    InsertToMiscProductTypes("sensor_sa_listener_product", products);
    return RET_OK;
}

int32_t MiscProductTypeParser::InsertToMiscProductTypes(const std::string &key, const std::vector<std::string> &value)
{
    std::unique_lock<std::shared_mutex> lock(lock_);
    miscProductTypes_[key] = value;
    return RET_OK;
}

void MiscProductTypeParser::PrintMiscProductTypes()
{
    CALL_INFO_TRACE;
    std::shared_lock<std::shared_mutex> lock(lock_);
    for (const auto &elem : miscProductTypes_) {
        MMI_HILOGI("bizKey:%{public}s", elem.first.c_str());
        for (const auto &product : elem.second) {
            MMI_HILOGI("product:%{public}s", product.c_str());
        }
    }
}

} // namespace MMI
} // namespace OHOS