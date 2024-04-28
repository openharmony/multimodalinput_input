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

#include "define_multimodal.h"
#include "input_event.h"
#include "key_event.h"
#include "mmi_log.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventLogHelper"

namespace OHOS {
namespace MMI {
class EventLogHelper final {
public:
    template <class T> static void PrintEventData(std::shared_ptr<T> event, int32_t actionType, int32_t itemNum);
    template <class T> static void PrintEventData(std::shared_ptr<T> event);

private:
    static void PrintInfoLog(const std::shared_ptr<KeyEvent> event)
    {
        std::vector<KeyEvent::KeyItem> eventItems{ event->GetKeyItems() };
        std::string isSimulate = event->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) ? "true" : "false";
        MMI_HILOGI("InputTracking id:%{public}d, KeyCode:%{public}d,ActionTime:%{public}" PRId64
            ",EventType:%{public}s,KeyAction:%{public}s,NumLock:%{public}d,CapsLock:%{public}d,"
            "ScrollLock:%{public}d,keyItemsCount:%{public}zu,DisplayId:%{public}d,IsSimulate:%{public}s",
            event->GetId(), event->GetKeyCode(), event->GetActionTime(),
            InputEvent::EventTypeToString(event->GetEventType()),
            KeyEvent::ActionToString(event->GetKeyAction()), event->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY),
            event->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY),
            event->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY), eventItems.size(),
            event->GetTargetDisplayId(), isSimulate.c_str());
        for (const auto &item : eventItems) {
            MMI_HILOGI("DeviceNumber:%{public}d,KeyCode:%{public}d,DownTime:%{public}" PRId64 ",IsPressed:%{public}d,",
            item.GetDeviceId(), item.GetKeyCode(), item.GetDownTime(), item.IsPressed());
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed keyCode: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += ("," + std::to_string(*cItr));
            }
            MMI_HILOGI("%{public}s]", tmpStr.c_str());
        }
    }

    static void Print(const std::shared_ptr<KeyEvent> event)
    {
        if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG) &&
            event->GetKeyCode() != KeyEvent::KEYCODE_POWER) {
            return;
        }
        std::vector<KeyEvent::KeyItem> eventItems{ event->GetKeyItems() };
        MMI_HILOGD("KeyCode:%{public}d,KeyIntention:%{public}d,ActionTime:%{public}" PRId64
            ",ActionStartTime:%{public}" PRId64
            ",EventType:%{public}s,Flag:%{public}d,KeyAction:%{public}s,NumLock:%{public}d,"
            "CapsLock:%{public}d,ScrollLock:%{public}d,EventNumber:%{public}d,keyItemsCount:%{public}zu",
            event->GetKeyCode(), event->GetKeyIntention(), event->GetActionTime(), event->GetActionStartTime(),
            InputEvent::EventTypeToString(event->GetEventType()), event->GetFlag(),
            KeyEvent::ActionToString(event->GetKeyAction()), event->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY),
            event->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY),
            event->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY),
            event->GetId(), eventItems.size());
        for (const auto &item : eventItems) {
            MMI_HILOGI("DeviceNumber:%{public}d,KeyCode:%{public}d,DownTime:%{public}" PRId64 ",IsPressed:%{public}d,"
                "GetUnicode:%{public}d", item.GetDeviceId(), item.GetKeyCode(), item.GetDownTime(), item.IsPressed(),
                item.GetUnicode());
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed keyCode: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += ("," + std::to_string(*cItr));
            }
            MMI_HILOGI("%{public}s]", tmpStr.c_str());
        }
    }

    __attribute__((no_sanitize("cfi")))
    static void PrintInfoLog(const std::shared_ptr<PointerEvent> event)
    {
        if (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE ||
            event->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_MOVE) {
            return;
        }
        std::vector<int32_t> pointerIds{ event->GetPointerIds() };
        std::string isSimulate = event->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) ? "true" : "false";
        MMI_HILOGI("InputTracking id:%{public}d, EventType:%{public}s, ActionTime:%{public}" PRId64
            ", PointerAction:%{public}s, SourceType:%{public}s, DisplayId:%{public}d"
            ", WindowId:%{public}d, DispatchTimes:%{public}d, IsSimulate:%{public}s",
            event->GetId(), InputEvent::EventTypeToString(event->GetEventType()), event->GetActionTime(),
            event->DumpPointerAction(), event->DumpSourceType(), event->GetTargetDisplayId(),
            event->GetTargetWindowId(), event->GetDispatchTimes(), isSimulate.c_str());
        for (const auto &pointerId : pointerIds) {
            PointerEvent::PointerItem item;
            if (!event->GetPointerItem(pointerId, item)) {
                MMI_HILOGE("Invalid pointer: %{public}d.", pointerId);
                return;
            }
            MMI_HILOGI("pointerId:%{public}d,DownTime:%{public}" PRId64 ",IsPressed:%{public}d,DisplayX:%{public}d,"
                "DisplayY:%{public}d,Pressure:%{public}.2f,LongAxis:%{public}d,ShortAxis:%{public}d,"
                "WindowId:%{public}d,DisplayXPos:%{public}f,DisplayYPos:%{public}f,WindowXPos:%{public}f,"
                "WindowYPos::%{public}f, OriginPointerId:%{public}d",
                pointerId, item.GetDownTime(), item.IsPressed(), item.GetDisplayX(), item.GetDisplayY(),
                item.GetPressure(), item.GetLongAxis(), item.GetShortAxis(), item.GetTargetWindowId(),
                item.GetDisplayXPos(), item.GetDisplayYPos(), item.GetWindowXPos(), item.GetWindowYPos(),
                item.GetOriginPointerId());
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed keyCode: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += ("," + std::to_string(*cItr));
            }
            MMI_HILOGI("%{public}s]", tmpStr.c_str());
        }
    }

    static void Print(const std::shared_ptr<PointerEvent> event)
    {
        std::vector<int32_t> pointerIds{ event->GetPointerIds() };
        std::string str;
        std::vector<uint8_t> buffer = event->GetBuffer();
        for (const auto &buff : buffer) {
            str += std::to_string(buff);
        }
        MMI_HILOGD("EventType:%{public}s,ActionTime:%{public}" PRId64 ",SensorInputTime:%{public}" PRIu64
            ",Action:%{public}d,ActionStartTime:%{public}" PRId64 ",Flag:%{public}d,PointerAction:%{public}s,"
            "SourceType:%{public}s,ButtonId:%{public}d,VerticalAxisValue:%{public}.2f,"
            "HorizontalAxisValue:%{public}.2f,PinchAxisValue:%{public}.2f,"
            "XAbsValue:%{public}.2f,YAbsValue:%{public}.2f,ZAbsValue:%{public}.2f,"
            "RzAbsValue:%{public}.2f,GasAbsValue:%{public}.2f,BrakeAbsValue:%{public}.2f,"
            "Hat0xAbsValue:%{public}.2f,Hat0yAbsValue:%{public}.2f,ThrottleAbsValue:%{public}.2f,"
            "PointerId:%{public}d,PointerCount:%{public}zu,EventNumber:%{public}d,"
            "BufferCount:%{public}zu,Buffer:%{public}s,MarkEnabled:%{public}d",
            InputEvent::EventTypeToString(event->GetEventType()), event->GetActionTime(), event->GetSensorInputTime(),
            event->GetAction(), event->GetActionStartTime(), event->GetFlag(),
            event->DumpPointerAction(), event->DumpSourceType(),
            event->GetButtonId(), event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH), event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_X),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_Y), event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_Z),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_RZ), event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_GAS),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_BRAKE),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0X),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_HAT0Y),
            event->GetAxisValue(PointerEvent::AXIS_TYPE_ABS_THROTTLE), event->GetPointerId(), pointerIds.size(),
            event->GetId(), buffer.size(), str.c_str(), event->IsMarkEnabled());

        for (const auto &pointerId : pointerIds) {
            PointerEvent::PointerItem item;
            if (!event->GetPointerItem(pointerId, item)) {
                MMI_HILOGE("Invalid pointer: %{public}d.", pointerId);
                return;
            }
            MMI_HILOGD("pointerId:%{public}d,DownTime:%{public}" PRId64 ",IsPressed:%{public}d,DisplayX:%{public}d,"
                "DisplayY:%{public}d,WindowX:%{public}d,WindowY:%{public}d,Width:%{public}d,Height:%{public}d,"
                "TiltX:%{public}.2f,TiltY:%{public}.2f,ToolDisplayX:%{public}d,ToolDisplayY:%{public}d,"
                "ToolWindowX:%{public}d,ToolWindowY:%{public}d,ToolWidth:%{public}d,ToolHeight:%{public}d,"
                "Pressure:%{public}.2f,ToolType:%{public}d,LongAxis:%{public}d,ShortAxis:%{public}d,RawDx:%{public}d,"
                "RawDy:%{public}d",
                pointerId, item.GetDownTime(), item.IsPressed(), item.GetDisplayX(), item.GetDisplayY(),
                item.GetWindowX(), item.GetWindowY(), item.GetWidth(), item.GetHeight(), item.GetTiltX(),
                item.GetTiltY(), item.GetToolDisplayX(), item.GetToolDisplayY(), item.GetToolWindowX(),
                item.GetToolWindowY(), item.GetToolWidth(), item.GetToolHeight(), item.GetPressure(),
                item.GetToolType(), item.GetLongAxis(), item.GetShortAxis(), item.GetRawDx(), item.GetRawDy());
        }
        std::vector<int32_t> pressedKeys = event->GetPressedKeys();
        std::vector<int32_t>::const_iterator cItr = pressedKeys.cbegin();
        if (cItr != pressedKeys.cend()) {
            std::string tmpStr = "Pressed keyCode: [" + std::to_string(*(cItr++));
            for (; cItr != pressedKeys.cend(); ++cItr) {
                tmpStr += ("," + std::to_string(*cItr));
            }
            MMI_HILOGD("%{public}s]", tmpStr.c_str());
        }
    }
};

template <class T> void EventLogHelper::PrintEventData(std::shared_ptr<T> event, int32_t actionType, int32_t itemNum)
{
    CHKPV(event);
    PrintInfoLog(event);
    if (HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        static int64_t nowTimeUSec = 0;
        static int32_t dropped = 0;
        if (event->GetAction() == EVENT_TYPE_POINTER) {
            if ((actionType == POINTER_ACTION_MOVE) && (event->GetActionTime() - nowTimeUSec <= TIMEOUT)) {
                ++dropped;
                return;
            }
            if (actionType == POINTER_ACTION_UP && itemNum == FINAL_FINGER) {
                MMI_HILOGD("This touch process discards %{public}d high frequent events", dropped);
                dropped = 0;
            }
            nowTimeUSec = event->GetActionTime();
        }
        EventLogHelper::Print(event);
    }
}

template <class T> void EventLogHelper::PrintEventData(std::shared_ptr<T> event)
{
    CHKPV(event);
    PrintInfoLog(event);
    if (HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG) ||
        (event->GetAction() == InputEvent::EVENT_TYPE_KEY)) {
        EventLogHelper::Print(event);
    }
}
} // namespace MMI
} // namespace OHOS
#endif // EVENT_LOG_HELPER_H
