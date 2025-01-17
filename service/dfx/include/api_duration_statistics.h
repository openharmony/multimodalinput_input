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

#ifndef API_DURATION_STATISTICS_H
#define API_DURATION_STATISTICS_H

#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace OHOS {
namespace MMI {
class ApiDurationStatistics {
public:
    enum Api : int32_t {
        IS_SCREEN_CAPTURE_WORKING = 0, // IScreenCaptureWorking
        GET_DEFAULT_DISPLAY, // GetDefaultDisplay
        GET_SYSTEM_ABILITY_MANAGER, // GetSystemAbilityManager
        IS_FOLDABLE, // IsFoldable
        IS_SCREEN_LOCKED, // IsScreenLocked
        RS_NOTIFY_TOUCH_EVENT, // RSInterfaces::NotifyTouchEvent
        RESOURCE_SCHEDULE_REPORT_DATA, // ResourceSchedule::ReportData
        GET_CUR_RENDERER_CHANGE_INFOS, // GetCurrentRendererChangeInfos
        GET_PROC_RUNNING_INFOS_BY_UID, // GetProcessRunningInfosByUserId
        TELEPHONY_CALL_MGR_INIT, // Telephony::CallManagerClient::Init
        TELEPHONY_CALL_MGR_MUTE_RINGER, // Telephony::CallManagerCLient::MuteRinger
        TELEPHONY_CALL_MGR_HANG_UP_CALL, // Telephony::CallManagerCLient::HangUpCall
        TELEPHONY_CALL_MGR_REJECT_CALL, // Telephony::CallManagerClient::RejectCall
        RE_SCREEN_MODE_CHANGE_LISTENER, // RegisterScreenModeChangeListener
        SET_ON_REMOTE_DIED_CALLBACK, // SetOnRemoteDiedCallback
        REG_SCREEN_CAPTURE_LISTENER, // RegisterScreenCaptureMonitorListener
        ABILITY_MGR_START_EXT_ABILITY, // StartExtensionAbility
        ABILITY_MGR_CLIENT_START_ABILITY, // AbilityManagerClient::StartAbility
        ABILITY_MGR_CONNECT_ABILITY, // AbilityManagerClient::ConnectAbility
        GET_RUNNING_PROCESS_INFO_BY_PID, // GetRunningProcessInfoByPid
        REGISTER_APP_DEBUG_LISTENER, // RegisterAppDebugListener
        UNREGISTER_APP_DEBUG_LISTENER, // UnregisterAppDebugListener
        PUBLISH_COMMON_EVENT, // PublishCommonEvent
        GET_VISIBILITY_WINDOW_INFO // GetVisibilityWindowInfo
    };

    enum class Threshold : int32_t {
        LESS_THAN_3MS = 3,
        LESS_THAN_5MS = 5,
        LESS_THAN_10MS = 10,
        GREATER_THAN_10MS = 11,
        MAX_DURATION = GREATER_THAN_10MS + 1
    };

    using DurationBox = std::unordered_map<Threshold, int32_t>;

    ApiDurationStatistics() = default;
    ~ApiDurationStatistics() = default;

    void RecordDuration(Api api, int32_t durationMS);
    void ResetApiStatistics();
    bool IsLimitMatched();
    std::unordered_map<Api, DurationBox> GetDurationBox();
    std::string ApiToString(Api api);
    std::vector<int32_t> GetDurationDistribution(Api api);


private:
    Threshold GetCurrentThreshold(int32_t duration);
private:
    std::unordered_map<Api, DurationBox> apiDurations_;
    std::atomic_int32_t apiCallingCount_ { 0 };
    static std::unordered_map<Api, std::string> apiNames_;
    static int32_t COUNT_LIMIT_TO_DFX_RADAR;
    std::shared_mutex mtx_;
};

} // namespace MMI
} // namespace OHOS
#endif // API_DURATION_STATISTICS_H