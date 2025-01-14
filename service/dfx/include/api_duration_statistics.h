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
#include <iostream>
#include <map>
#include <string>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <vector>
#include <mutex>

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
        GET_CURRENT_RENDERER_CHANGE_INFOS, // GetCurrentRendererChangeInfos
        GET_PROCESS_RUNNING_INFOS_BY_USER_ID, // GetProcessRunningInfosByUserId
        TELEPHONY_CALL_MGR_CLIENT_INIT, // Telephony::CallManagerClient::Init
        TELEPHONY_CALL_MGR_CLIENT_MUTE_RINGER, // Telephony::CallManagerCLient::MuteRinger
        TELEPHONY_CALL_MGR_HANG_UP_CALL, // Telephony::CallManagerCLient::HangUpCall
        TELEPHONY_CALL_MGR_REJECT_CALL, // Telephony::CallManagerClient::RejectCall
        REGISTER_SCREEN_MODE_CHANGE_LISTENER, // RegisterScreenModeChangeListener
        SET_ON_REMOTE_DIED_CALLBACK, // SetOnRemoteDiedCallback
        REGISTER_SCREEN_CAPTURE_MONITOR_LISTENER, // RegisterScreenCaptureMonitorListener
        ABILITY_MGR_CLIENT_START_EXTENSION_ABILITY, // StartExtensionAbility
        ABILITY_MGR_CLIENT_START_ABILITY, // AbilityManagerClient::StartAbility
        ABILITY_MGR_CLIENT_CONNECT_ABILITY, // AbilityManagerClient::ConnectAbility
        GET_RUNNING_PROCESS_INFO_BY_PID, // GetRunningProcessInfoByPid
        REGISTER_APP_DEBUG_LISTENER, // RegisterAppDebugListener
        UNREGISTER_APP_DEBUG_LISTENER, // UnregisterAppDebugListener
    };

    enum class Threshold : int32_t {
        LESS_THAN_ZERO = 0,
        LESS_THAN_3MS = 3,
        LESS_THAN_5MS = 5,
        LESS_THAN_10MS = 10,
        LESS_THAN_50MS = 50,
        LESS_THAN_100MS = 100,
        LESS_THAN_200MS = 200,
        MAX_DURATION = LESS_THAN_200MS + 1
    };

    using DurationBox = std::unordered_map<Threshold, int32_t>;

    ApiDurationStatistics() = default;
    ~ApiDurationStatistics() = default;

    void RecordDuration(Api api, int32_t durationMS);
    void ResetApiStatistics();
    bool IsLimitMatched();
    std::unordered_map<Api, DurationBox> GetDurationBox();
    std::string ApiToString(Api api);

private:
    Threshold GetCurrentThreshold(int32_t duration);

private:
    std::unordered_map<Api, DurationBox> apiDurations_;
    std::atomic_int32_t apiCallingCount_ { 0 };
    static std::unordered_map<Api, std::string> apiNames_;
    std::mutex mtx_;
    static int32_t COUNT_LIMIT_TO_DFX_RADAR;
};

} // namespace MMI
} // namespace OHOS
#endif // API_DURATION_STATISTICS_H