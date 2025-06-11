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
const char* ON_KEY_EVENT { "OnKeyEvent" };
const char* ON_TOUCH_EVENT { "OnTouchEvent" };
const char* ON_POINTER_EVENT { "OnPointerEvent" };
const char* KEY_EVENT_DISPATCH { "KeyEventDispatch" };
const char* TOUCH_EVENT_DISPATCH { "touchEventDispatch" };
const char* POINTER_EVENT_DISPATCH { "PointerEventDispatch" };
const char* KEY_EVENT_SUBSCRIBE { "KeyEventSubscribe" };
const char* POINTER_EVENT_INTERCEPT { "PointerEventIntercept" };
const char* TOUCH_EVENT_INTERCEPT { "TouchEventIntercept" };
const char* KEY_EVENT_INTERCEPT { "KeyEventIntercept" };
const char* ON_START_EVENT { "StartEvent" };
const char* ON_LAUNCH_EVENT { "LaunchEvent" };
const char* ON_STOP_EVENT { "StopEvent" };
constexpr int32_t START_ID { 1 };
constexpr int32_t LAUNCH_ID { 2 };
constexpr int32_t STOP_ID { 3 };
} // namespace

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_KEY_EVENT, keyId, "", nullptr);
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
            StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_POINTER_EVENT, eventId,
                "", nullptr);
            HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report pointerId:" + std::to_string(eventId) +
                + ", type: " + pointerEvent->DumpPointerAction());
        } else {
            StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_TOUCH_EVENT, eventId,
                "", nullptr);
            HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "service report touchId:" + std::to_string(eventId) +
                + ", type: " + pointerEvent->DumpPointerAction());
        }
    } else {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_POINTER_EVENT, eventId);
        } else {
            FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_TOUCH_EVENT, eventId);
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
    FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_KEY_EVENT, keyId);
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent, TraceBtn traceBtn, HandlerType handlerType)
{
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    if (traceBtn == TRACE_START) {
        switch (handlerType) {
            case KEY_INTERCEPT_EVENT: {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_INTERCEPT, keyId,
                    "", nullptr);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client Intercept keyCode");
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_SUBSCRIBE, keyId,
                    "", nullptr);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client subscribe keyCode");
                break;
            }
            case KEY_DISPATCH_EVENT: {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_DISPATCH, keyId,
                    "", nullptr);
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
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_INTERCEPT, keyId);
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_SUBSCRIBE, keyId);
                break;
            }
            case KEY_DISPATCH_EVENT: {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, KEY_EVENT_DISPATCH, keyId);
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
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_DISPATCH, eventId,
                    "", nullptr);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client dispatch pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_DISPATCH, eventId,
                    "", nullptr);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client dispatch touchId:" + std::to_string(eventId));
            }
        } else {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_INTERCEPT, eventId,
                    "", nullptr);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT,
                    "client Intercept pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_INTERCEPT, eventId,
                    "", nullptr);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "client Intercept touchId:" + std::to_string(eventId));
            }
        }
    } else {
        if (handlerType == POINT_DISPATCH_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_DISPATCH, eventId);
            } else {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_DISPATCH, eventId);
            }
        }
        if (handlerType == POINT_INTERCEPT_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, POINTER_EVENT_INTERCEPT, eventId);
            } else {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, TOUCH_EVENT_INTERCEPT, eventId);
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
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_START_EVENT, START_ID,
                    "", nullptr);
                checkKeyCode = "crossing startId:" + std::to_string(START_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
            case LAUNCH_EVENT: {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_LAUNCH_EVENT, LAUNCH_ID,
                    "", nullptr);
                checkKeyCode = "crossing launchId:" + std::to_string(LAUNCH_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
            case STOP_EVENT: {
                StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_STOP_EVENT, STOP_ID,
                    "", nullptr);
                checkKeyCode = "crossing stopId:" + std::to_string(STOP_ID);
                HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, checkKeyCode);
                break;
            }
        }
    } else {
        switch (eventType) {
            case START_EVENT: {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_START_EVENT, START_ID);
                break;
            }
            case LAUNCH_EVENT: {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_LAUNCH_EVENT, LAUNCH_ID);
                break;
            }
            case STOP_EVENT: {
                FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, ON_STOP_EVENT, STOP_ID);
                break;
            }
        }
    }
}

void BytraceAdapter::StartIpcServer(uint32_t code)
{
    std::string traceInfo = "ipcServerHandle code:" + std::to_string(code);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopIpcServer()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartPackageEvent(const std::string& msg)
{
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, msg.c_str(), "");
}

void BytraceAdapter::StopPackageEvent()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHandleInput(int32_t code)
{
    std::string traceInfo = "originEventHandle code:" + std::to_string(code);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopHandleInput()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHandleTracker(int32_t pointerId)
{
    std::string traceInfo = "pointerId:" + std::to_string(pointerId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopHandleTracker()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartConsumer(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    std::string traceInfo = "eventConsume pointerEventId:" + std::to_string(pointerEvent->GetId());
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopConsumer()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartConsumer(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    std::string traceInfo = "eventConsume keyEventId:" + std::to_string(keyEvent->GetId());
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StartPostTaskEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    std::string traceInfo = "startpostEvent pointerEventId:" + std::to_string(pointerEvent->GetId());
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StartPostTaskEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    std::string traceInfo = "startpostEvent keyEventId:" + std::to_string(keyEvent->GetId());
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopPostTaskEvent()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartSocketHandle(int32_t msgId)
{
    std::string traceInfo = "socketMsgHandle msgId:" + std::to_string(msgId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopSocketHandle()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartDevListener(const std::string& type, int32_t deviceId)
{
    std::string traceInfo = "device listener type:" + type + ", deviceid:" + std::to_string(deviceId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopDevListener()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartLaunchAbility(int32_t type, const std::string& bundleName)
{
    std::string traceInfo = "launchAbility type:" + std::to_string(type) + ", bundleName:" + bundleName;
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopLaunchAbility()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartMarkedTracker(int32_t eventId)
{
    std::string traceInfo = "markProcessed eventId:" + std::to_string(eventId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopMarkedTracker()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartTouchEvent(int32_t pointerId)
{
    std::string traceInfo = "startTouchEvent pointerId:" + std::to_string(pointerId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopTouchEvent()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartToolType(int32_t toolType)
{
    std::string traceInfo = "current ToolType:" + std::to_string(toolType);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopToolType()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartTouchUp(int32_t pointerId)
{
    std::string traceInfo = "startTouchUp pointerId:" + std::to_string(pointerId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopTouchUp()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartUpdateDisplayMode(const std::string &modeMsg)
{
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, modeMsg.c_str(), "");
}

void BytraceAdapter::StopUpdateDisplayMode()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartDataShare(const std::string &key)
{
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, key.c_str(), "");
}

void BytraceAdapter::StopDataShare()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartRsSurfaceNode(int32_t displayId)
{
    std::string traceInfo = "pointerWindow displayId:" + std::to_string(displayId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopRsSurfaceNode()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartFoldState(bool state)
{
    std::string traceInfo = state ? "true" : "false";
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopFoldState()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartWindowVisible(int32_t pid)
{
    std::string traceInfo = "get visibility window info:" + std::to_string(pid);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopWindowVisible()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHardPointerRender(uint32_t width, uint32_t height, uint32_t bufferId, uint32_t screenId,
    int32_t style)
{
    std::string traceInfo = "hard pointer render buffer width:" + std::to_string(width)
        + " height:" + std::to_string(height)
        + " bufferId:" + std::to_string(bufferId)
        + " screenId:" + std::to_string(screenId)
        + " style:" + std::to_string(style);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopHardPointerRender()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartSoftPointerRender(uint32_t width, uint32_t height, int32_t style)
{
    std::string traceInfo = "soft pointer render buffer width:" + std::to_string(width)
        + " height:" + std::to_string(height)
        + " style:" + std::to_string(style);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopSoftPointerRender()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}

void BytraceAdapter::StartHardPointerMove(uint32_t width, uint32_t height, uint32_t bufferId, uint32_t screenId)
{
    std::string traceInfo = "hard pointer move width:" + std::to_string(width)
        + " height:" + std::to_string(height)
        + " bufferId:" + std::to_string(bufferId)
        + " screenId:" + std::to_string(screenId);
    StartTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT, traceInfo.c_str(), "");
}

void BytraceAdapter::StopHardPointerMove()
{
    FinishTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_MULTIMODALINPUT);
}
} // namespace MMI
} // namespace OHOS