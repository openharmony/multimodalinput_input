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

#ifndef WHITELIST_DATA_SHARE_ACCESSOR_H
#define WHITELIST_DATA_SHARE_ACCESSOR_H

#include <atomic>
#include <string>
#include <shared_mutex>
#include <unordered_set>
#include <vector>

namespace OHOS {
namespace MMI {
class WhitelistDataShareAccessor {
public:
    WhitelistDataShareAccessor(const WhitelistDataShareAccessor&) = delete;
    WhitelistDataShareAccessor& operator=(const WhitelistDataShareAccessor&) = delete;
    static WhitelistDataShareAccessor& GetInstance();
    bool IsWhitelisted(const std::string &bundleName);
 
private:
    WhitelistDataShareAccessor();
    ~WhitelistDataShareAccessor() = default;
    int32_t Init();
    int32_t InitializeImpl();
    int32_t AddWhitelistObserver();
    int32_t ReadWhitelistFromDB(std::vector<std::string> &whitelist);
    void OnUpdate(const std::string &whitelist);
    static std::vector<std::string> Split(const std::string& str, char delimiter = ';');
    void UpdateWhitelist(const std::vector<std::string> &whitelist);
 
private:
    std::shared_mutex mtx_;
    std::atomic_bool initialized_ { false };
    std::unordered_set<std::string> whitelist_;
};
 
} // namespace MMI
} // namespace OHOS
#endif // WHITELIST_DATA_SHARE_ACCESSOR_H