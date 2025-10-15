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

 
#include "bundle_name_parser.h"

#include "util.h"

#include <cJSON.h>

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "BundleNameParser"

namespace OHOS {
namespace MMI {
namespace {
constexpr std::string_view bundleNameConfigDir { "/etc/multimodalinput/bundle_name_config.json" };
constexpr int32_t maxJsonArraySize { 100 };
} // namespace

BundleNameParser& BundleNameParser::GetInstance()
{
    static BundleNameParser instance;
    return instance;
}

int32_t BundleNameParser::Init()
{
    CALL_DEBUG_ENTER;
    static std::once_flag init_flag;
    static int32_t initRes = RET_ERR;
    std::call_once(init_flag, [this]() {
        initRes = InitializeImpl();
    });
    return initRes;
}

int32_t BundleNameParser::InitializeImpl()
{
    CALL_INFO_TRACE;
    std::string jsonStr = ReadJsonFile(std::string(bundleNameConfigDir));
    if (jsonStr.empty()) {
        MMI_HILOGE("Read bundleName failed");
        return RET_ERR;
    }
    JsonParser parser(jsonStr.c_str());
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Not valid object");
        return RET_ERR;
    }
    if (ParseBundleNameMap(parser) != RET_OK) {
        MMI_HILOGE("ParseBundleNameMap failed");
        return RET_ERR;
    }
    PrintBundleNames();
    return RET_OK;
}

std::string BundleNameParser::GetBundleName(const std::string &key)
{
    if (Init() != RET_OK) {
        MMI_HILOGE("Init failed");
        return "";
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (bundleNames_.find(key) != bundleNames_.end()) {
        return bundleNames_[key];
    }
    MMI_HILOGW("No %{public}s matched.", key.c_str());
    return "";
}

int32_t BundleNameParser::ParseBundleNameMap(const JsonParser &jsonParser)
{
    if (!cJSON_IsObject(jsonParser.Get())) {
        MMI_HILOGE("The jsonParser is not object");
        return RET_ERR;
    }
    cJSON *bundleNameMapJson = cJSON_GetObjectItemCaseSensitive(jsonParser.Get(), "bundle_name_map");
    if (!cJSON_IsArray(bundleNameMapJson)) {
        MMI_HILOGE("bundleNameMapJson is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(bundleNameMapJson);
    if (arraySize > maxJsonArraySize) {
        MMI_HILOGW("arraySize is too much, truncate it");
    }
    for (int32_t i = 0; i < std::min(arraySize, maxJsonArraySize); i++) {
        cJSON* bundleNameItemJson = cJSON_GetArrayItem(bundleNameMapJson, i);
        CHKPC(bundleNameItemJson);
        BundleNameItem bundleNameItem;
        if (ParseBundleNameItem(bundleNameItemJson, bundleNameItem) != RET_OK) {
            MMI_HILOGE("ParseBundleNameItem failed");
            continue;
        }
        std::unique_lock<std::shared_mutex> lock(lock_);
        bundleNames_.insert({ bundleNameItem.placeHolder, bundleNameItem.bundleName });
    }
    return RET_OK;
}

int32_t BundleNameParser::ParseBundleNameItem(const cJSON *json, BundleNameItem &bundleNameItem)
{
    if (JsonParser::ParseString(json, "placeholder", bundleNameItem.placeHolder) != RET_OK) {
        MMI_HILOGW("Parse placeholder failed");
        return RET_ERR;
    }
    if (JsonParser::ParseString(json, "bundle_name", bundleNameItem.bundleName) != RET_OK) {
        MMI_HILOGW("Parse bundle_name failed");
        return RET_ERR;
    }
    return RET_OK;
}

void BundleNameParser::PrintBundleNames()
{
    CALL_INFO_TRACE;
    std::shared_lock<std::shared_mutex> lock(lock_);
    for (const auto &bundleName: bundleNames_) {
        MMI_HILOGI("key:%{public}s -> value:%{public}s", bundleName.first.c_str(), bundleName.second.c_str());
    }
}

} // namespace MMI
} // namespace OHOS