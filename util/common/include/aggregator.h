/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INPUT_AGGREGATOR_H
#define INPUT_AGGREGATOR_H

#include <iostream>
#include <map>
#include <set>
#include <string>
#include <utility>

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
class Aggregator {
public:
    Aggregator(std::function<int32_t(int32_t, int32_t, std::function<void()>)> addTimer,
               std::function<int32_t(int32_t)> resetTimer, uint32_t maxRecordCount = 100)
        : addTimer_(std::move(addTimer)), resetTimer_(std::move(resetTimer)), maxRecordCount_(maxRecordCount)
    {}

    bool Record(const LogHeader &lh, const std::string &key, const std::string &record);

    ~Aggregator();

private:
    struct RecordInfo {
        std::string record;
        std::chrono::system_clock::time_point timestamp;
    };
    std::string key_;
    std::vector<RecordInfo> records_;
    std::function<int32_t(int32_t, int32_t, std::function<void()>)> addTimer_;
    std::function<int32_t(int32_t)> resetTimer_;
    int32_t timerId_ { -1 };
    uint32_t maxRecordCount_ { 0 };

    void FlushRecords(const LogHeader &lh, const std::string &key = "", const std::string &extraRecord = "");
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_AGGREGATOR_H
