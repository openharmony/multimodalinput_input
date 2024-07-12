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

#ifndef EVENT_LOG_HELPER_H
#define EVENT_LOG_HELPER_H

#include <memory>

#include "parameters.h"

#include "define_multimodal.h"
#include "input_event.h"
#include "key_event.h"
#include "mmi_log.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventLogHelper"

namespace OHOS {
namespace MMI {
static constexpr std::string_view InfoTrackingDict =
        "Info-InputTracking-Dict: "
        "AT-ActionTime, CL-CapsLock, DI-DisplayId, DPT-DispatchTimes, DT-DownTime, DX-DisplayX, DXP-DisplayXPos,"
        " DY-DisplayY, DYP-DisplayYPos, ET-EventType, GU-GetUnicode, I-id, IP-IsPressed, IR-IsRepeat, SI-IsSimulate,"
        " KA-KeyAction, KC-KeyCode, KIC-keyItemsCount, LA-LongAxis, NL-NumLock, OPI-OriginPointerId, PA-PointerAction,"
        " PI-pointerId, P-Pressure, SA-ShortAxis, SL-ScrollLock, ST-SourceType, WI-WindowId, WXP-WindowXPos, "
        "WYP-WindowYPos, PBS-PressedButtonsSize";

static constexpr std::string_view DebugTrackingDict =
        "Debug-InputTracking-Dict: "
        "A-Action, AST-ActionStartTime, B-Buffer, BC-BufferCount, BI-ButtonId, BAV-BrakeAbsValue, F-Flag,"
        " GAV-GenericAxisValue, HAV-HorizontalAxisValue, HXAV-Hat0xAbsValue, HYAV-Hat0yAbsValue, KI-KeyIntention,"
        " ME-MarkEnabled, PAV-PinchAxisValue, PC-PointerCount, RZAV-RzAbsValue, SIT-SensorInputTime, "
        "TAV-ThrottleAbsValue, TX-TiltX, TY-TiltY, VAV-VerticalAxisValue, W-Width, WX-WindowX, WY-WindowY,"
        " XAV-XAbsValue, YAV-YAbsValue, ZAV-ZAbsValue, RAV-RotateAxisValue";

class EventLogHelper final {
public:
    template<class T>
    static void PrintEventData(std::shared_ptr<T> event, int32_t actionType, int32_t itemNum, const LogHeader &lh);

    template<class T> static void PrintEventData(std::shared_ptr<T> event, const LogHeader &lh);

    static std::string GetBetaUserType()
    {
        if (userType_ == "") {
            userType_ = OHOS::system::GetParameter("const.logsystem.versiontype", "default");
        }
        if (userType_ == "beta") {
            return "DEVICE_BETA_USER";
        } else if (userType_ == "default") {
            return "DEVICE_BETA_DEFAULT";
        } else {
            return "DEVICE_BETA_OTHER";
        }
    }

    static bool IsBetaVersion()
    {
        return GetBetaUserType() == "DEVICE_BETA_USER";
    }

private:
    static int32_t infoDictCount_;
    static int32_t debugDictCount_;
    static thread_local std::string userType_;
    static constexpr int32_t printRate_ = 50;

    static void PrintInfoDict()
    {
        if ((++infoDictCount_) % printRate_ == 0) {
            infoDictCount_ = 0;
            MMI_HILOGI("%{public}s", InfoTrackingDict.data());
        }
    }

    static void PrintDebugDict()
    {
        if ((++debugDictCount_) % printRate_ == 0) {
            debugDictCount_ = 0;
            MMI_HILOGD("%{public}s", DebugTrackingDict.data());
        }
    }

    static void PrintInfoLog(const std::shared_ptr<KeyEvent> event, const LogHeader &lh)
    {
        PrintInfoDict();
        std::vector<KeyEvent::KeyItem> eventItems{ event->GetKeyItems() };
        std::string isSimulate = event->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) ? "true" : "false";
        std::string isRepeat = event->IsRepeat() ? "true" : "false";
        if (!IsBetaVersion()) {
            MMI_HILOG_HEADER(LOG_INFO, lh, "See InputTracking-Dict, I:%{public}d" ", ET:%{public}s,"
                "KA:%{public}s, KIC:%{public}zu, DI:%{public}d, IR:%{public}s, SI:%{public}s",
                event->GetId(), InputEvent::EventTypeToString(event->GetEventType()),
                KeyEvent::ActionToString(event->GetKeyAction()), eventItems.size(),
                event->GetTargetDisplayId(), isRepeat.c_str(), isSimulate.c_str());
        } else {
            MMI_HILOG_HEADER(LOG_INFO, lh, "See InputTracking-Dict, I:%{public}d, KC:%{public}d, AT:%{public}" PRId64
                ", ET:%{public}s, KA:%{public}s, NL:%{public}d, CL:%{public}d, SL:%{public}d, KIC:%{public}zu, "
                "DI:%{public}d, IR:%{public}s, SI:%{public}s",
                event->GetId(), event->GetKeyCode(), event->GetActionTime(),
                InputEvent::EventTypeToString(event->GetEventType()),
                KeyEvent::ActionToString(event->GetKeyAction()), event->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY),
                event->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY),
                event->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY), eventItems.size(),
                event->GetTargetDisplayId(), isRepeat.c_str(), isSimulate.c_str());
        }
       
        for (const auto &item : eventItems) {
            if (!IsBetaVersion()) {
                MMI_HILOG_HEADER(LOG_INFO, lh, "DN:%{public}d" PRId64
                ", IP:%{public}d,", item.GetDeviceId(), item.IsPressed());
            } else {
                MMI_HILOG_HEADER(LOG_INFO, lh, "DN:%{public}d, KC:%{public}d, DT:%{public}" PRId64
                ", IP:%{public}d,", item.GetDeviceId(), item.GetKeyCode(), item.GetDownTime(), item.IsPressed());
            }
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed KC: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += ("," + std::to_string(*cItr));
            }
            MMI_HILOG_HEADER(LOG_INFO, lh, "%{public}s]", tmpStr.c_str());
        }
    }

    static void Print(const std::shared_ptr<KeyEvent> event, const LogHeader &lh)
    {
        if (!HiLogIsLoggable(lh.domain, lh.func, LOG_DEBUG) && event->GetKeyCode() != KeyEvent::KEYCODE_POWER) {
            return;
        }
        PrintDebugDict();
        PrintInfoDict();
        std::vector<KeyEvent::KeyItem> eventItems{ event->GetKeyItems() };
        if (!IsBetaVersion()) {
            MMI_HILOG_HEADER(LOG_DEBUG, lh, "KI:%{public}d, " "ET:%{public}s, F:%{public}d, KA:%{public}s, "
                "EN:%{public}d , KIC:%{public}zu",
                event->GetKeyIntention(), InputEvent::EventTypeToString(event->GetEventType()), event->GetFlag(),
                KeyEvent::ActionToString(event->GetKeyAction()), event->GetId(), eventItems.size());
        } else {
            MMI_HILOG_HEADER(LOG_DEBUG, lh, "KC:%{public}d, KI:%{public}d, AT:%{public}" PRId64", AST:%{public}" PRId64
                ", ET:%{public}s, F:%{public}d, KA:%{public}s, NL:%{public}d, CL:%{public}d, SL:%{public}d"
                ", EN:%{public}d, KIC:%{public}zu",
                event->GetKeyCode(), event->GetKeyIntention(), event->GetActionTime(), event->GetActionStartTime(),
                InputEvent::EventTypeToString(event->GetEventType()), event->GetFlag(),
                KeyEvent::ActionToString(event->GetKeyAction()), event->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY),
                event->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY),
                event->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY), event->GetId(), eventItems.size());
        }
        for (const auto &item : eventItems) {
            if (!IsBetaVersion()) {
                MMI_HILOG_HEADER(LOG_INFO, lh, "DN:%{public}d, IP:%{public}d, GU:%{public}d",
                    item.GetDeviceId(), item.IsPressed(), item.GetUnicode());
            } else {
                MMI_HILOG_HEADER(LOG_INFO, lh, "DN:%{public}d, KC:%{public}d, DT:%{public}" PRId64 ", IP:%{public}d, "
                    "GU:%{public}d", item.GetDeviceId(), item.GetKeyCode(), item.GetDownTime(), item.IsPressed(),
                    item.GetUnicode());
            }
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed keyCode: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += ("," + std::to_string(*cItr));
            }
            MMI_HILOG_HEADER(LOG_INFO, lh, "%{public}s]", tmpStr.c_str());
        }
    }

    __attribute__((no_sanitize("cfi")))
    static void PrintInfoLog(const std::shared_ptr<PointerEvent> event, const LogHeader &lh)
    {
        if (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE ||
            event->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_MOVE ||
            event->GetPointerAction() == PointerEvent::POINTER_ACTION_HOVER_MOVE ||
            event->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_UPDATE ||
            event->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_UPDATE ||
            event->GetPointerAction() == PointerEvent::POINTER_ACTION_ROTATE_UPDATE ||
            event->GetPointerAction() == PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE) {
            return;
        }
        PrintInfoDict();
        std::vector<int32_t> pointerIds{ event->GetPointerIds() };
        std::string isSimulate = event->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) ? "true" : "false";
        MMI_HILOGD("See InputTracking-Dict I:%{public}d, ET:%{public}s, AT:%{public}" PRId64
            ", PA:%{public}s, ST:%{public}s, DI:%{public}d, WI:%{public}d, DPT:%{public}d"
            ", SI:%{public}s, PBS:%{public}zu",
            event->GetId(), InputEvent::EventTypeToString(event->GetEventType()), event->GetActionTime(),
            event->DumpPointerAction(), event->DumpSourceType(), event->GetTargetDisplayId(),
            event->GetTargetWindowId(), event->GetDispatchTimes(), isSimulate.c_str(),
            event->GetPressedButtons().size());
        for (const auto &pointerId : pointerIds) {
            PointerEvent::PointerItem item;
            if (!event->GetPointerItem(pointerId, item)) {
                MMI_HILOG_HEADER(LOG_ERROR, lh, "Invalid pointer:%{public}d", pointerId);
                return;
            }
            if (!IsBetaVersion()) {
                MMI_HILOG_HEADER(LOG_INFO, lh, "PI:%{public}d, IP:%{public}d, P:%{public}.2f, WI:%{public}d, "
                    "OPI:%{public}d, SI:%{public}s",
                    pointerId, item.IsPressed(), item.GetPressure(), item.GetTargetWindowId(),
                    item.GetOriginPointerId(), isSimulate.c_str());
            } else {
                if (event->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
                    MMI_HILOG_HEADER(LOG_INFO, lh, "PI:%{public}d, DT:%{public}" PRId64 ", IP:%{public}d,DX:%d, DY:%d,"
                        "P:%{public}.2f, LA:%{public}d, SA:%{public}d, WI:%{public}d, DXP:%f, DYP:%f, WXP:%f, WYP:%f, "
                        "OPI:%{public}d",
                        pointerId, item.GetDownTime(), item.IsPressed(), item.GetDisplayX(), item.GetDisplayY(),
                        item.GetPressure(), item.GetLongAxis(), item.GetShortAxis(), item.GetTargetWindowId(),
                        item.GetDisplayXPos(), item.GetDisplayYPos(), item.GetWindowXPos(), item.GetWindowYPos(),
                        item.GetOriginPointerId());
                    continue;
                }
                MMI_HILOG_HEADER(LOG_INFO, lh, "PI:%{public}d, DT:%{public}" PRId64 ", IP:%{public}d, DX:%{public}d, "
                    "DY:%{public}d, P:%{public}.2f, LA:%{public}d, SA:%{public}d, WI:%{public}d, DXP:%{public}f,"
                    "DYP:%{public}f, WXP:%{public}f, WYP:%{public}f, OPI:%{public}d, SI:%{public}s",
                    pointerId, item.GetDownTime(), item.IsPressed(), item.GetDisplayX(), item.GetDisplayY(),
                    item.GetPressure(), item.GetLongAxis(), item.GetShortAxis(), item.GetTargetWindowId(),
                    item.GetDisplayXPos(), item.GetDisplayYPos(), item.GetWindowXPos(), item.GetWindowYPos(),
                    item.GetOriginPointerId(), isSimulate.c_str());
            }
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed keyCode: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += ("," + std::to_string(*cItr));
            }
            MMI_HILOG_HEADER(LOG_INFO, lh, "%{public}s]", tmpStr.c_str());
        }
    }

    static void Print(const std::shared_ptr<PointerEvent> event, const LogHeader &lh)
    {
        PrintDebugDict();
        std::vector<int32_t> pointerIds{ event->GetPointerIds() };
        std::string str;
        std::vector<uint8_t> buffer = event->GetBuffer();
        for (const auto &buff : buffer) {
            str += std::to_string(buff);
        }
        if (!IsBetaVersion()) {
            MMI_HILOG_HEADER(LOG_DEBUG, lh, "ET:%{public}s, SIT:%{public}" PRIu64 ", A:%{public}d, "
                ", F:%{public}d, PA:%{public}s, ST:%{public}s, BI:%{public}d, PI:%{public}d, PC:%{public}zu, "
                "EN:%{public}d, BC:%{public}zu, ME:%{public}d",
                InputEvent::EventTypeToString(event->GetEventType()),
                event->GetSensorInputTime(), event->GetAction(), event->GetFlag(),
                event->DumpPointerAction(), event->DumpSourceType(), event->GetButtonId(), event->GetPointerId(),
                pointerIds.size(), event->GetId(), buffer.size(), event->IsMarkEnabled());
        } else {
            MMI_HILOG_HEADER(LOG_DEBUG, lh, "ET:%{public}s, AT:%{public}" PRId64 ", SIT:%{public}" PRId64
                ",A:%{public}d, AST:%{public}" PRId64 ", F:%{public}d, PA:%{public}s, ST:%{public}s, BI:%{public}d, "
                "VAV:%{public}.5f, HAV:%{public}.5f, PAV:%{public}.5f, PAV:%{public}.5f, XAV:%{public}.5f,"
                "YAV:%{public}.5f, ZAV:%{public}.5f, RZAV:%{public}.5f, GAV:%{public}.5f, BAV:%{public}.5f, "
                "HXAV:%{public}.5f, HYAV:%{public}.5f, TAV:%{public}.5f,PI:%{public}d, PC:%{public}zu, EN:%{public}d, "
                "BC:%{public}zu, B:%{public}s, ME:%{public}d",
                InputEvent::EventTypeToString(event->GetEventType()), event->GetActionTime(),
                event->GetSensorInputTime(), event->GetAction(), event->GetActionStartTime(), event->GetFlag(),
                event->DumpPointerAction(), event->DumpSourceType(), event->GetButtonId(),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH), event->GetAxisValue(PointerEvent::AXIS_TYPE_ROTATE),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_X), event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_Y),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_Z), event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_RZ),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_GAS),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_BRAKE),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0Y),
                event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_THROTTLE), event->GetPointerId(), pointerIds.size(),
                event->GetId(), buffer.size(), str.c_str(), event->IsMarkEnabled());
        }

        for (const auto &pointerId : pointerIds) {
            PointerEvent::PointerItem item;
            if (!event->GetPointerItem(pointerId, item)) {
                MMI_HILOG_HEADER(LOG_ERROR, lh, "Invalid pointer:%{public}d", pointerId);
                return;
            }
            if (!IsBetaVersion()) {
                MMI_HILOG_HEADER(LOG_DEBUG, lh,
                    "PI:%{public}d, IP:%{public}d, P:%{public}.2f, ToolType:%{public}d",
                    pointerId, item.IsPressed(), item.GetPressure(), item.GetToolType());
            } else {
                if (event->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
                    MMI_HILOG_HEADER(LOG_DEBUG, lh,"PI:%{public}d, DT:%{public}" PRId64 ", IP:%{public}d, DX:%d, DY:%d"
                        ", WX:%d, WY:%d, W:%{public}d, H:%{public}d, TX:%.2f, TY:%.2f, TDX:%d, TDY:%d, ToolWX:%d, "
                        "ToolWY:%d, ToolW:%{public}d, ToolH:%{public}d, P:%{public}.2f, ToolType:%{public}d, "
                        "LA:%{public}d, SA:%{public}d, RawDx:%d, RawDy:%d",
                        pointerId, item.GetDownTime(), item.IsPressed(), item.GetDisplayX(), item.GetDisplayY(),
                        item.GetWindowX(), item.GetWindowY(), item.GetWidth(), item.GetHeight(), item.GetTiltX(),
                        item.GetTiltY(), item.GetToolDisplayX(), item.GetToolDisplayY(), item.GetToolWindowX(),
                        item.GetToolWindowY(), item.GetToolWidth(), item.GetToolHeight(), item.GetPressure(),
                        item.GetToolType(), item.GetLongAxis(), item.GetShortAxis(), item.GetRawDx(), item.GetRawDy());
                    continue;
                }
            }
            if (!IsBetaVersion()) {
                MMI_HILOG_HEADER(LOG_DEBUG, lh,
                    "PI:%{public}d" ", IP:%{public}d, P:%{public}.2f, ToolType:%{public}d",
                    pointerId, item.IsPressed(), item.GetPressure(), item.GetToolType());
            } else {
                MMI_HILOG_HEADER(LOG_DEBUG, lh,
                    "PI:%{public}d, DT:%{public}" PRId64 ", IP:%{public}d, DX:%{public}d, DY:%{public}d, WX:%{public}d"
                    ", WY:%{public}d, W:%{public}d, H:%{public}d, TX:%{public}.2f, TY:%{public}.2f, TDX:%{public}d, "
                    "TDY:%{public}d, ToolWX:%{public}d, ToolWY:%{public}d, ToolW:%{public}d, ToolH:%{public}d, "
                    "P:%{public}.2f, ToolType:%{public}d, LA:%{public}d, SA:%{public}d, RawDx:%{public}d, "
                    "RawDy:%{public}d",
                    pointerId, item.GetDownTime(), item.IsPressed(), item.GetDisplayX(),
                    item.GetDisplayY(), item.GetWindowX(), item.GetWindowY(), item.GetWidth(), item.GetHeight(),
                    item.GetTiltX(), item.GetTiltY(), item.GetToolDisplayX(), item.GetToolDisplayY(),
                    item.GetToolWindowX(), item.GetToolWindowY(), item.GetToolWidth(), item.GetToolHeight(),
                    item.GetPressure(), item.GetToolType(), item.GetLongAxis(), item.GetShortAxis(), item.GetRawDx(),
                    item.GetRawDy());
            }
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed keyCode: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += (", " + std::to_string(*cItr));
            }
            MMI_HILOG_HEADER(LOG_DEBUG, lh, "%{public}s]", tmpStr.c_str());
        }
    }
};

template <class T> void EventLogHelper::PrintEventData(std::shared_ptr<T> event, int32_t actionType, int32_t itemNum,
                                                       const LogHeader &lh)
{
    CHKPV(event);
    PrintInfoLog(event, lh);
    if (HiLogIsLoggable(lh.domain, lh.tag, LOG_DEBUG)) {
        static int64_t nowTimeUSec = 0;
        static int32_t dropped = 0;
        if (event->GetAction() == EVENT_TYPE_POINTER) {
            if ((actionType == POINTER_ACTION_MOVE) && (event->GetActionTime() - nowTimeUSec <= TIMEOUT)) {
                ++dropped;
                return;
            }
            if (actionType == POINTER_ACTION_UP && itemNum == FINAL_FINGER) {
                MMI_HILOG_HEADER(LOG_DEBUG, lh, "This touch process discards %{public}d high frequent events", dropped);
                dropped = 0;
            }
            nowTimeUSec = event->GetActionTime();
        }
        EventLogHelper::Print(event, lh);
    }
}

template <class T> void EventLogHelper::PrintEventData(std::shared_ptr<T> event, const LogHeader &lh)
{
    CHKPV(event);
    PrintInfoLog(event, lh);
    if (HiLogIsLoggable(lh.domain, lh.tag, LOG_DEBUG) ||
        (event->GetAction() == InputEvent::EVENT_TYPE_KEY)) {
        EventLogHelper::Print(event, lh);
    }
}
} // namespace MMI
} // namespace OHOS
#endif // EVENT_LOG_HELPER_H
