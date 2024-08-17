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
#include "hitrace_meter.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "BytraceAdapter"

namespace OHOS {
namespace MMI {
namespace {
const std::string onKeyEvent { "OnKeyEvent" };
const std::string onTouchEvent { "OnTouchEvent" };
const std::string onPointerEvent { "OnPointerEvent" };
const std::string keyEventDispatch { "KeyEventDispatch" };
const std::string touchEventDispatch { "touchEventDispatch" };
const std::string pointerEventDispatch { "PointerEventDispatch" };
const std::string keyEventSubscribe { "KeyEventSubscribe" };
const std::string pointerEventIntercept { "PointerEventIntercept" };
const std::string touchEventIntercept { "TouchEventIntercept" };
const std::string keyEventIntercept { "KeyEventIntercept" };
const std::string startEvent { "StartEvent" };
const std::string launchEvent { "LaunchEvent" };
const std::string stopEvent { "StopEvent" };
constexpr int32_t START_ID { 1 };
constexpr int32_t LAUNCH_ID { 2 };
constexpr int32_t STOP_ID { 3 };
} // namespace

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, onKeyEvent, keyId);
    HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report keyId=" + std::to_string(keyId));
}

std::string BytraceAdapter::GetKeyTraceString(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPS(keyEvent);
    return KeyEvent::ActionToString(keyEvent->GetKeyAction());
}

std::string BytraceAdapter::GetPointerTraceString(std::shared_ptr<PointerEvent> pointerEvent)
{
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
}

void BytraceAdapter::StartBytrace(std::shared_ptr<PointerEvent> pointerEvent, TraceBtn traceBtn)
{
    CHKPV(pointerEvent);
    int32_t eventId = pointerEvent->GetId();
    if (traceBtn == TRACE_START) {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, onPointerEvent, eventId);
            HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report pointerId:" + std::to_string(eventId) +
                + ", type: " + pointerEvent->DumpPointerAction());
        } else {
            StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, onTouchEvent, eventId);
            HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report touchId:" + std::to_string(eventId) +
                + ", type: " + pointerEvent->DumpPointerAction());
        }
    } else {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, onPointerEvent, eventId);
        } else {
            FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, onTouchEvent, eventId);
        }
    }
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> key, HandlerType handlerType)
{
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
    FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, onKeyEvent, keyId);
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent, TraceBtn traceBtn, HandlerType handlerType)
{
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    [[ maybe_unused ]] int32_t keyCode = keyEvent->GetKeyCode();
    if (traceBtn == TRACE_START) {
        switch (handlerType) {
            case KEY_INTERCEPT_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventIntercept, keyId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client Intercept keyCode");
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventSubscribe, keyId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client subscribe keyCode");
                break;
            }
            case KEY_DISPATCH_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventDispatch, keyId);
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
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventIntercept, keyId);
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventSubscribe, keyId);
                break;
            }
            case KEY_DISPATCH_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventDispatch, keyId);
                break;
            }
            default: {
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "Unknown keyCode");
                break;
            }
        }
    }
}

void BytraceAdapter::StartBytrace(
    std::shared_ptr<PointerEvent> pointerEvent, TraceBtn traceBtn, HandlerType handlerType)
{
    CHKPV(pointerEvent);
    int32_t eventId = pointerEvent->GetId();
    if (traceBtn == TRACE_START) {
        if (handlerType == POINT_DISPATCH_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, pointerEventDispatch, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client dispatch pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, touchEventDispatch, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client dispatch touchId:" + std::to_string(eventId));
            }
        } else {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, pointerEventIntercept, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT,
                    "client Intercept pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, touchEventIntercept, eventId);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client Intercept touchId:" + std::to_string(eventId));
            }
        }
    } else {
        if (handlerType == POINT_DISPATCH_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, pointerEventDispatch, eventId);
            } else {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, touchEventDispatch, eventId);
            }
        }
        if (handlerType == POINT_INTERCEPT_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, pointerEventIntercept, eventId);
            } else {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, touchEventIntercept, eventId);
            }
        }
    }
}

void BytraceAdapter::StartBytrace(TraceBtn traceBtn, EventType eventType)
{
    std::string checkKeyCode;
    if (traceBtn == TRACE_START) {
        switch (eventType) {
            case START_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, startEvent, START_ID);
                checkKeyCode = "crossing startId:" + std::to_string(START_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
            case LAUNCH_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, launchEvent, LAUNCH_ID);
                checkKeyCode = "crossing launchId:" + std::to_string(LAUNCH_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
            case STOP_EVENT: {
                StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, stopEvent, STOP_ID);
                checkKeyCode = "crossing stopId:" + std::to_string(STOP_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
        }
    } else {
        switch (eventType) {
            case START_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventIntercept, START_ID);
                break;
            }
            case LAUNCH_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventIntercept, LAUNCH_ID);
                break;
            }
            case STOP_EVENT: {
                FinishAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, keyEventIntercept, STOP_ID);
                break;
            }
        }
    }
}

void BytraceAdapter::StartIpcServer(uint32_t code)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "ipcServerHandle code:" + std::to_string(code));
}

void BytraceAdapter::StopIpcServer()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartPackageEvent(const std::string& msg)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, msg);
}

void BytraceAdapter::StopPackageEvent()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHandleInput(int32_t code)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "originEventHandle code:" + std::to_string(code));
}

void BytraceAdapter::StopHandleInput()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHandleTracker(int32_t pointerId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "pointerId:" + std::to_string(pointerId));
}

void BytraceAdapter::StopHandleTracker()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartConsumer(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "eventConsume pointerEventId:" + std::to_string(pointerEvent->GetId()));
}

void BytraceAdapter::StopConsumer()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartConsumer(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "eventConsume keyEventId:" + std::to_string(keyEvent->GetId()));
}

void BytraceAdapter::StartPostTaskEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "startpostEvent pointerEventId:" +
        std::to_string(pointerEvent->GetId()));
}

void BytraceAdapter::StartPostTaskEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "startpostEvent keyEventId:" +
        std::to_string(keyEvent->GetId()));
}

void BytraceAdapter::StopPostTaskEvent()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartSocketHandle(int32_t msgId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "socketMsgHandle msgId:" + std::to_string(msgId));
}

void BytraceAdapter::StopSocketHandle()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartLaunchAbility(int32_t type, const std::string& bundleName)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT,
        "launchAbility type:" + std::to_string(type) + ", bundleName:" + bundleName);
}

void BytraceAdapter::StopLaunchAbility()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartMarkedTracker(int32_t eventId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "markProcessed eventId:" + std::to_string(eventId));
}

void BytraceAdapter::StopMarkedTracker()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartTouchEvent(int32_t pointerId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "startTouchEvent pointerId:" + std::to_string(pointerId));
}

void BytraceAdapter::StopTouchEvent()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}
} // namespace MMI
} // namespace OHOS