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
    using ApiDurationsType = std::unordered_map<ApiDurationStatistics::Api, ApiDurationStatistics::DurationBox>;
}

int32_t ApiDurationStatistics::COUNT_LIMIT_TO_DFX_RADAR { 1000 };
std::unordered_map<ApiDurationStatistics::Api, std::string> ApiDurationStatistics::apiNames_ {
    { ApiDurationStatistics::Api::IS_SCREEN_CAPTURE_WORKING, "IS_SCREEN_CAPTURE_WORKING" },
    { ApiDurationStatistics::Api::GET_DEFAULT_DISPLAY, "GET_DEFAULT_DISPLAY" },
    { ApiDurationStatistics::Api::GET_SYSTEM_ABILITY_MANAGER, "GET_SYSTEM_ABILITY_MANAGER" },
    { ApiDurationStatistics::Api::IS_FOLDABLE, "IS_FOLDABLE" },
    { ApiDurationStatistics::Api::IS_SCREEN_LOCKED, "IS_SCREEN_LOCKED" },
    { ApiDurationStatistics::Api::RS_NOTIFY_TOUCH_EVENT, "RS_NOTIFY_TOUCH_EVENT" },
    { ApiDurationStatistics::Api::RESOURCE_SCHEDULE_REPORT_DATA, "RESOURCE_SCHEDULE_REPORT_DATA" },
    { ApiDurationStatistics::Api::GET_CUR_RENDERER_CHANGE_INFOS, "GET_CUR_RENDERER_CHANGE_INFOS" },
    { ApiDurationStatistics::Api::GET_PROC_RUNNING_INFOS_BY_UID, "GET_PROC_RUNNING_INFOS_BY_UID" },
    { ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_INIT, "TELEPHONY_CALL_MGR_INIT" },
    { ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_MUTE_RINGER, "TELEPHONY_CALL_MGR_MUTE_RINGER" },
    { ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_HANG_UP_CALL, "TELEPHONY_CALL_MGR_HANG_UP_CALL" },
    { ApiDurationStatistics::Api::TELEPHONY_CALL_MGR_REJECT_CALL, "TELEPHONY_CALL_MGR_REJECT_CALL" },
    { ApiDurationStatistics::Api::RE_SCREEN_MODE_CHANGE_LISTENER, "RE_SCREEN_MODE_CHANGE_LISTENER" },
    { ApiDurationStatistics::Api::SET_ON_REMOTE_DIED_CALLBACK, "SET_ON_REMOTE_DIED_CALLBACK" },
    { ApiDurationStatistics::Api::REG_SCREEN_CAPTURE_LISTENER,
        "REGISTER_SCREEN_CAPTURE_MONITOR_LISTENER" },
    { ApiDurationStatistics::Api::ABILITY_MGR_START_EXT_ABILITY,
        "ABILITY_MGR_START_EXT_ABILITY" },
    { ApiDurationStatistics::Api::ABILITY_MGR_CLIENT_START_ABILITY, "ABILITY_MGR_CLIENT_START_ABILITY" },
    { ApiDurationStatistics::Api::ABILITY_MGR_CONNECT_ABILITY, "ABILITY_MGR_CLIENT_CONNECT_ABILITY" },
    { ApiDurationStatistics::Api::GET_RUNNING_PROCESS_INFO_BY_PID, "GET_RUNNING_PROCESS_INFO_BY_PID" },
    { ApiDurationStatistics::Api::REGISTER_APP_DEBUG_LISTENER, "REGISTER_APP_DEBUG_LISTENER" },
    { ApiDurationStatistics::Api::UNREGISTER_APP_DEBUG_LISTENER, "UNREGISTER_APP_DEBUG_LISTENER" },
    { ApiDurationStatistics::Api::PUBLISH_COMMON_EVENT, "PUBLISH_COMMON_EVENT" },
    { ApiDurationStatistics::Api::GET_VISIBILITY_WINDOW_INFO, "GET_VISIBILITY_WINDOW_INFO" }
};

void ApiDurationStatistics::RecordDuration(Api api, int32_t durationMS)
{
    auto threshold = GetCurrentThreshold(durationMS);
    {
        std::unique_lock<std::shared_mutex> lock(mtx_);
        apiDurations_[api][threshold] += 1;
    }
    ++apiCallingCount_;
}

void ApiDurationStatistics::ResetApiStatistics()
{
    apiCallingCount_ = 0;
    std::unique_lock<std::shared_mutex> lock(mtx_);
    apiDurations_.clear();
}

bool ApiDurationStatistics::IsLimitMatched()
{
    return apiCallingCount_ >= COUNT_LIMIT_TO_DFX_RADAR;
}

ApiDurationsType ApiDurationStatistics::GetDurationBox()
{
    std::shared_lock<std::shared_mutex> lock(mtx_);
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
    if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_3MS)) {
        return Threshold::LESS_THAN_3MS;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_5MS)) {
        return Threshold::LESS_THAN_5MS;
    } else if (duration <= static_cast<int32_t> (Threshold::LESS_THAN_10MS)) {
        return Threshold::LESS_THAN_10MS;
    } else {
        return Threshold::GREATER_THAN_10MS;
    }
}

std::vector<int32_t> ApiDurationStatistics::GetDurationDistribution(Api api)
{
    std::shared_lock<std::shared_mutex> lock(mtx_);
    if (apiDurations_.find(api)== apiDurations_.end()) {
        return { 0, 0, 0, 0 };
    }
    auto durationBox = apiDurations_[api];

    std::vector<int32_t> durations;
    if (durationBox.find(Threshold::LESS_THAN_3MS) != durationBox.end()) {
        durations.push_back(durationBox[Threshold::LESS_THAN_3MS]);
    } else {
        durations.push_back(0);
    }
    if (durationBox.find(Threshold::LESS_THAN_5MS) != durationBox.end()) {
        durations.push_back(durationBox[Threshold::LESS_THAN_5MS]);
    } else {
        durations.push_back(0);
    }
    if (durationBox.find(Threshold::LESS_THAN_10MS) != durationBox.end()) {
        durations.push_back(durationBox[Threshold::LESS_THAN_10MS]);
    } else {
        durations.push_back(0);
    }
    if (durationBox.find(Threshold::GREATER_THAN_10MS) != durationBox.end()) {
        durations.push_back(durationBox[Threshold::GREATER_THAN_10MS]);
    } else {
        durations.push_back(0);
    }
    return durations;
}

} // namespace MMI
} // namespace OHOS
