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

#include "hitrace_meter.h"
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
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    StartAsyncTrace(HITRACE_TAG_MULTIMODALINPUT, ON_KEY_EVENT, keyId);
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
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> key, HandlerType handlerType)
{
    CHKPV(key);
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
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent, TraceBtn traceBtn, HandlerType handlerType)
{
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
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
}

void BytraceAdapter::StartBytrace(
    std::shared_ptr<PointerEvent> pointerEvent, TraceBtn traceBtn, HandlerType handlerType)
{
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
}

void BytraceAdapter::StartBytrace(TraceBtn traceBtn, EventType eventType)
{
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

void BytraceAdapter::StartDevListener(const std::string& type, int32_t deviceId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT,
        "device listener type:" + type + ", deviceid:" + std::to_string(deviceId));
}

void BytraceAdapter::StopDevListener()
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

void BytraceAdapter::StartToolType(int32_t toolType)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "current ToolType:" + std::to_string(toolType));
}

void BytraceAdapter::StopToolType()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartTouchUp(int32_t pointerId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "startTouchUp pointerId:" + std::to_string(pointerId));
}

void BytraceAdapter::StopTouchUp()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartUpdateDisplayMode(const std::string &modeMsg)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, modeMsg);
}

void BytraceAdapter::StopUpdateDisplayMode()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartDataShare(const std::string &key)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, key);
}

void BytraceAdapter::StopDataShare()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartRsSurfaceNode(int32_t displayId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "pointerWindow displayId:" + std::to_string(displayId));
}

void BytraceAdapter::StopRsSurfaceNode()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartFoldState(bool state)
{
    std::string foldState = state ? "true" : "false";
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, foldState);
}

void BytraceAdapter::StopFoldState()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartWindowVisible(int32_t pid)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "get visibility window info:" + std::to_string(pid));
}

void BytraceAdapter::StopWindowVisible()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHardPointerRender(uint32_t width, uint32_t height, uint32_t bufferId, uint32_t screenId,
    int32_t style)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT,"hard pointer render buffer width:" + std::to_string(width)
        + " height:" + std::to_string(height)
        + " bufferId:" + std::to_string(bufferId)
        + " screenId:" + std::to_string(screenId)
        + " style:" + std::to_string(style));
}

void BytraceAdapter::StopHardPointerRender()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartSoftPointerRender(uint32_t width, uint32_t height, int32_t style)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "soft pointer render buffer width:" + std::to_string(width)
        + " height:" + std::to_string(height)
        + " style:" + std::to_string(style));
}

void BytraceAdapter::StopSoftPointerRender()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHardPointerMove(uint32_t width, uint32_t height, uint32_t bufferId, uint32_t screenId)
{
    StartTrace(HITRACE_TAG_MULTIMODALINPUT, "hard pointer move width:" + std::to_string(width)
        + " height:" + std::to_string(height)
        + " bufferId:" + std::to_string(bufferId)
        + " screenId:" + std::to_string(screenId));
}

void BytraceAdapter::StopHardPointerMove()
{
    FinishTrace(HITRACE_TAG_MULTIMODALINPUT);
}
} // namespace MMI
} // namespace OHOS