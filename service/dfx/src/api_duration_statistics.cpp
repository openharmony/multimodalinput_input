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

#include "api_duration_statistics.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ApiDurationStatistics"

namespace OHOS {
namespace MMI {
namespace {
    const std::string UNKNOWN_API { "UNKNOWN_API" };
}

int32_t ApiDurationStatistics::COUNT_LIMIT_TO_DFX_RADAR { 1000 };

ApiDurationStatistics::ApiDurationStatistics() { }

void ApiDurationStatistics::RecordDuration(Api api, int32_t durationMS)
{
    auto threshold = GetCurrentThreshold(durationMS);
    {
        std::lock_guard<std::mutex> guard(mtx_);
        apiDurations_[api][threshold] += 1;
    }
    ++apiCallingCount_;
}

void ApiDurationStatistics::ResetApiStatistics()
{
    apiCallingCount_ = 0;
    std::lock_guard<std::mutex> guard(mtx_);
    apiDurations_.clear();
}

bool ApiDurationStatistics::IsLimitMatched()
{
    return apiCallingCount_ >= COUNT_LIMIT_TO_DFX_RADAR;
}

std::unordered_map<Api, DurationBox> ApiDurationStatistics::GetDurationBox()
{
    std::lock_guard<std::mutex> guard(mtx_);
    return apiDurations_;
}

std::string ApiDurationStatistics::ApiToString(Api api)
{
    if (apiNames_.find(api) != apiNames_.end()) {
        return apiNames_[api];
    }
    return UNKNOWN_API;
}

ApiDurationStatistics::Threshold ApiDurationStatistics::GetCurrentThreshold(int32_t duration)
{
    if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_ZERO)) {
        return Threshold::LESS_THAN_ZERO;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_3MS)) {
        return Threshold::LESS_THAN_3MS;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_5MS)) {
        return Threshold::LESS_THAN_5MS;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_10MS)) {
        return Threshold::LESS_THAN_10MS;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_50MS)) {
        return Threshold::LESS_THAN_50MS;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_100MS)) {
        return Threshold::LESS_THAN_100MS;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_200MS)) {
        return Threshold::LESS_THAN_200MS;
    } else {
        return Threshold::MAX_DURATION;
    }
}

} // namespace MMI
} // namespace OHOS
