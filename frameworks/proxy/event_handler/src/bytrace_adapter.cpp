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
#include "bytrace_adapter.h"

#include <string>

#include "define_multimodal.h"
#ifdef HITRACE_ENABLED
#include "hitrace_meter.h"
#endif // HITRACE_ENABLED
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "BytraceAdapter"

namespace OHOS {
namespace MMI {
namespace {
const std::string ON_KEY_EVENT { "OnKeyEvent" };
const std::string ON_TOUCH_EVENT { "OnTouchEvent" };
const std::string ON_POINTER_EVENT { "OnPointerEvent" };
const std::string KEY_EVENT_DISPATCH { "KeyEventDispatch" };
const std::string TOUCH_EVENT_DISPATCH { "touchEventDispatch" };
const std::string POINTER_EVENT_DISPATCH { "PointerEventDispatch" };
const std::string KEY_EVENT_SUBSCRIBE { "KeyEventSubscribe" };
const std::string POINTER_EVENT_INTERCEPT { "PointerEventIntercept" };
const std::string TOUCH_EVENT_INTERCEPT { "TouchEventIntercept" };
const std::string KEY_EVENT_INTERCEPT { "KeyEventIntercept" };
const std::string ON_START_EVENT { "StartEvent" };
const std::string ON_LAUNCH_EVENT { "LaunchEvent" };
const std::string ON_STOP_EVENT { "StopEvent" };
constexpr int32_t START_ID { 1 };
constexpr int32_t LAUNCH_ID { 2 };
constexpr int32_t STOP_ID { 3 };
} // namespace

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent)
{
#ifdef HITRACE_ENABLED
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_KEY_EVENT, keyId);
    HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report keyId=" + std::to_string(keyId));
#endif // HITRACE_ENABLED
}

std::string BytraceAdapter::GetKeyTraceString(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPS(keyEvent);
    return KeyEvent::ActionToString(keyEvent->GetKeyAction());
}

std::string BytraceAdapter::GetPointerTraceString(std::shared_ptr<PointerEvent> pointerEvent)
{
#ifdef HITRACE_ENABLED
    CHKPS(pointerEvent);
    std::vector<PointerEvent::PointerItem> pointerItems;
    std::vector<int32_t> pointerIds{ pointerEvent->GetPointerIds() };
    for (const auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        if (!pointerEvent->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Invalid pointer:%{public}d", pointerId);
            return "";
        }
        pointerItems.emplace_back(item);
    }
    std::string traceStr;
    for (const auto &item : pointerItems) {
        auto id = item.GetPointerId();
        auto displayX = item.GetDisplayX();
        auto displayY = item.GetDisplayY();
        traceStr += " [";
        traceStr += "id: " + std::to_string(id);
        traceStr += ", x:" + std::to_string(displayX);
        traceStr += ", y:" + std::to_string(displayY);
        traceStr += "]";
    }
    return traceStr;
#else
    return "";
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartBytrace(std::shared_ptr<PointerEvent> pointerEvent, TraceBtn traceBtn)
{
#ifdef HITRACE_ENABLED
    CHKPV(pointerEvent);
    int32_t eventId = pointerEvent->GetId();
    if (traceBtn == TRACE_START) {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_POINTER_EVENT, eventId);
            HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report pointerId:" + std::to_string(eventId) +
                + ", type: " + pointerEvent->DumpPointerAction());
        } else {
            StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_TOUCH_EVENT, eventId);
            HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report touchId:" + std::to_string(eventId) +
                + ", type: " + pointerEvent->DumpPointerAction());
        }
    } else {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_POINTER_EVENT, eventId);
        } else {
            FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_TOUCH_EVENT, eventId);
        }
    }
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> key, HandlerType handlerType)
{
#ifdef HITRACE_ENABLED
    CHKPV(key);
    [[ maybe_unused ]] int32_t keyCode = key->GetKeyCode();
    std::string checkKeyCode;
    switch (handlerType) {
        case KEY_INTERCEPT_EVENT: {
            checkKeyCode = "Intercept keyCode";
            break;
        }
        case KEY_LAUNCH_EVENT: {
            checkKeyCode = "Launch keyCode";
            break;
        }
        case KEY_SUBSCRIBE_EVENT: {
            checkKeyCode = "Subscribe keyCode";
            break;
        }
        case KEY_DISPATCH_EVENT: {
            checkKeyCode = "Dispatch keyCode";
            break;
        }
        default: {
            checkKeyCode = "Unknown keyCode";
            break;
        }
    }
    HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
    int32_t keyId = key->GetId();
    FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_KEY_EVENT, keyId);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent, TraceBtn traceBtn, HandlerType handlerType)
{
#ifdef HITRACE_ENABLED
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    [[ maybe_unused ]] int32_t keyCode = keyEvent->GetKeyCode();
    if (traceBtn == TRACE_START) {
        switch (handlerType) {
            case KEY_INTERCEPT_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_INTERCEPT, keyId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client Intercept keyCode");
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_SUBSCRIBE, keyId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client subscribe keyCode");
                break;
            }
            case KEY_DISPATCH_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_DISPATCH, keyId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client dispatch keyCode");
                break;
            }
            default: {
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "Unknown keyCode");
                break;
            }
        }
    } else {
        switch (handlerType) {
            case KEY_INTERCEPT_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_INTERCEPT, keyId);
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_SUBSCRIBE, keyId);
                break;
            }
            case KEY_DISPATCH_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_DISPATCH, keyId);
                break;
            }
            default: {
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "Unknown keyCode");
                break;
            }
        }
    }
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartBytrace(
    std::shared_ptr<PointerEvent> pointerEvent, TraceBtn traceBtn, HandlerType handlerType)
{
#ifdef HITRACE_ENABLED
    CHKPV(pointerEvent);
    int32_t eventId = pointerEvent->GetId();
    if (traceBtn == TRACE_START) {
        if (handlerType == POINT_DISPATCH_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_DISPATCH, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client dispatch pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_DISPATCH, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client dispatch touchId:" + std::to_string(eventId));
            }
        } else {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_INTERCEPT, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT,
                    "client Intercept pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_INTERCEPT, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client Intercept touchId:" + std::to_string(eventId));
            }
        }
    } else {
        if (handlerType == POINT_DISPATCH_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_DISPATCH, eventId);
            } else {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_DISPATCH, eventId);
            }
        }
        if (handlerType == POINT_INTERCEPT_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_INTERCEPT, eventId);
            } else {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_INTERCEPT, eventId);
            }
        }
    }
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartBytrace(TraceBtn traceBtn, EventType eventType)
{
#ifdef HITRACE_ENABLED
    std::string checkKeyCode;
    if (traceBtn == TRACE_START) {
        switch (eventType) {
            case START_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_START_EVENT, START_ID);
                checkKeyCode = "crossing startId:" + std::to_string(START_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
            case LAUNCH_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_LAUNCH_EVENT, LAUNCH_ID);
                checkKeyCode = "crossing launchId:" + std::to_string(LAUNCH_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
            case STOP_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_STOP_EVENT, STOP_ID);
                checkKeyCode = "crossing stopId:" + std::to_string(STOP_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
        }
    } else {
        switch (eventType) {
            case START_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_INTERCEPT, START_ID);
                break;
            }
            case LAUNCH_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_INTERCEPT, LAUNCH_ID);
                break;
            }
            case STOP_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_INTERCEPT, STOP_ID);
                break;
            }
        }
    }
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartIpcServer(uint32_t code)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "ipcServerHandle code:" + std::to_string(code));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopIpcServer()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartPackageEvent(const std::string& msg)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, msg);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopPackageEvent()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartHandleInput(int32_t code)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "originEventHandle code:" + std::to_string(code));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopHandleInput()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartHandleTracker(int32_t pointerId)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "pointerId:" + std::to_string(pointerId));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopHandleTracker()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartConsumer(std::shared_ptr<PointerEvent> pointerEvent)
{
#ifdef HITRACE_ENABLED
    CHKPV(pointerEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "eventConsume pointerEventId:" + std::to_string(pointerEvent->GetId()));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopConsumer()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartConsumer(std::shared_ptr<KeyEvent> keyEvent)
{
#ifdef HITRACE_ENABLED
    CHKPV(keyEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "eventConsume keyEventId:" + std::to_string(keyEvent->GetId()));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartPostTaskEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
#ifdef HITRACE_ENABLED
    CHKPV(pointerEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "startpostEvent pointerEventId:" +
        std::to_string(pointerEvent->GetId()));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartPostTaskEvent(std::shared_ptr<KeyEvent> keyEvent)
{
#ifdef HITRACE_ENABLED
    CHKPV(keyEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "startpostEvent keyEventId:" +
        std::to_string(keyEvent->GetId()));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopPostTaskEvent()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartSocketHandle(int32_t msgId)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "socketMsgHandle msgId:" + std::to_string(msgId));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopSocketHandle()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartDevListener(const std::string& type, int32_t deviceId)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT,
        "device listener type:" + type + ", deviceid:" + std::to_string(deviceId));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopDevListener()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartLaunchAbility(int32_t type, const std::string& bundleName)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT,
        "launchAbility type:" + std::to_string(type) + ", bundleName:" + bundleName);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopLaunchAbility()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartMarkedTracker(int32_t eventId)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "markProcessed eventId:" + std::to_string(eventId));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopMarkedTracker()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StartTouchEvent(int32_t pointerId)
{
#ifdef HITRACE_ENABLED
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "startTouchEvent pointerId:" + std::to_string(pointerId));
#endif // HITRACE_ENABLED
}

void BytraceAdapter::StopTouchEvent()
{
#ifdef HITRACE_ENABLED
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
#endif // HITRACE_ENABLED
}
} // namespace MMI
} // namespace OHOS