/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DFX_HISYSEVENT_H
#define DFX_HISYSEVENT_H

#include <string>

#include "hisysevent.h"

#include "input_device_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "pointer_event.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class DfxHisysevent {
public:
    struct DispCastTime {
        uint32_t sampleCount;
        uint32_t totalTimes;
        uint32_t below10msTimes;
        uint32_t below25msTimes;
        uint32_t below50msTimes;
        uint32_t above50msTimes;
    };
    struct ComboStartCastTime {
        uint32_t totalTimes;
        uint32_t below10msTimes;
        uint32_t below30msTimes;
        uint32_t below50msTimes;
        uint32_t above50msTimes;
    };
    struct ClientConnectData {
        int32_t pid { -1 };
        int32_t uid { -1 };
        int32_t moduleType { -1 };
        std::string programName;
        int32_t serverFd { -1 };
    };

    enum TOUCHPAD_SETTING_CODE {
        TOUCHPAD_SCROLL_SETTING = 1,
        TOUCHPAD_SCROLL_DIR_SETTING,
        TOUCHPAD_TAP_SETTING,
        TOUCHPAD_SWIPE_SETTING,
        TOUCHPAD_PINCH_SETTING,
        TOUCHPAD_POINTER_SPEED_SETTING,
        TOUCHPAD_RIGHT_CLICK_SETTING,
        TOUCHPAD_ROTATE_SETTING
    };

    static void OnDeviceConnect(int32_t id, OHOS::HiviewDFX::HiSysEvent::EventType type);
    static void OnDeviceDisconnect(int32_t id, OHOS::HiviewDFX::HiSysEvent::EventType type);
    static void OnClientConnect(const ClientConnectData &data, OHOS::HiviewDFX::HiSysEvent::EventType type);
    static void OnClientDisconnect(const SessionPtr& secPtr, int32_t fd,
        OHOS::HiviewDFX::HiSysEvent::EventType type);
    static void OnUpdateTargetPointer(std::shared_ptr<PointerEvent> pointer, int32_t fd,
        OHOS::HiviewDFX::HiSysEvent::EventType type);
    static void OnUpdateTargetKey(std::shared_ptr<KeyEvent> key, int32_t fd,
        OHOS::HiviewDFX::HiSysEvent::EventType type);
    static void OnFocusWindowChanged(int32_t oldFocusWindowId, int32_t newFocusWindowId,
        int32_t oldFocusWindowPid, int32_t newFocusWindowPid);
    static void OnZorderWindowChanged(int32_t oldZorderFirstWindowId, int32_t newZorderFirstWindowId,
        int32_t oldZorderFirstWindowPid, int32_t newZorderFirstWindowPid);
    static void OnLidSwitchChanged(int32_t lidSwitch);
    static void ApplicationBlockInput(const SessionPtr& sess);
    static void CalcKeyDispTimes();
    static void CalcPointerDispTimes();
    static void CalcComboStartTimes(int32_t keyDownDuration);
    static void ReportDispTimes();
    static void ReportComboStartTimes();
    static void ReportPowerInfo(std::shared_ptr<KeyEvent> key, OHOS::HiviewDFX::HiSysEvent::EventType type);
    static inline void GetComboStartTime()
    {
        comboStartTime_ = GetSysClockTime();
    }
    static inline void GetDispStartTime()
    {
        dispatchStartTime_ = GetSysClockTime();
    }
    static void ReportTouchpadSettingState(TOUCHPAD_SETTING_CODE settingCode, bool flag);
    static void ReportTouchpadSettingState(TOUCHPAD_SETTING_CODE settingCode, int32_t value);
    static void StatisticTouchpadGesture(std::shared_ptr<PointerEvent> pointerEvent);
    static void ReportKnuckleClickEvent();
    static void ReportScreenCaptureGesture();
    static void ReportSingleKnuckleDoubleClickEvent(int32_t intervalTime, int32_t distanceInterval);
    static void ReportFailIfInvalidTime(const std::shared_ptr<PointerEvent> touchEvent, int32_t intervalTime);
    static void ReportFailIfInvalidDistance(const std::shared_ptr<PointerEvent> touchEvent, float distance);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    static void ReportMagicCursorColorChange(std::string fill_Color, std::string stroke_Color);
    static void ReportMagicCursorShapeChange(std::string fill_Code, OHOS::MMI::MOUSE_ICON mouse_Style);
    static void ReportMagicCursorSizeChange(std::string fill_Code, std::string mouse_Size);
    static void ReportMagicCursorFault(std::string error_Code, std::string error_Name);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    static void ReportSmartShotSuccTimes();
    static void ReportKnuckleGestureTrackLength(int32_t knuckleGestureTrackLength);
    static void ReportKnuckleGestureTrackTime(const std::vector<int64_t> &gestureTimeStamps);
    static void ReportKnuckleGestureFaildTimes();
    static void ReportKnuckleDrawSSuccessTimes();
    static void ReportKnuckleGestureFromFailToSuccessTime(int32_t intervalTime);
    static void ReportKnuckleGestureFromSuccessToFailTime(int32_t intervalTime);
    static void ReportScreenRecorderGesture(int32_t intervalTime);
    static void ReportFailIfKnockTooFast();
    static void ReportFailIfOneSuccTwoFail(const std::shared_ptr<PointerEvent> touchEvent);
    static std::string GetTpVendorName();
    static std::string GetAccVendorName();
    static std::string GetLcdInfo();

private:
    static inline int64_t dispatchStartTime_ { 0 };
    static inline int64_t comboStartTime_ { 0 };
    static inline DispCastTime dispCastTime_ { 0 };
    static inline ComboStartCastTime comboStartCastTime_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // BYTRACE_ADAPTER_H
