/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "bytrace_adapter.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "BytraceAdapter" };
} // namespace
namespace {
    std::string onKeyEvent = "OnKeyEvent";
    std::string onTouchEvent = "OnTouchEvent";
    std::string onPointerEvent = "OnPointerEvent";
    std::string keyEventDispatch = "KeyEventDispatch";
    std::string touchEventDispatch = "touchEventDispatch";
    std::string pointerEventDispatch = "PointerEventDispatch";
    std::string keyEventSubscribe = "KeyEventSubscribe";
    std::string pointerEventIntercept = "PointerEventIntercept";
    std::string touchEventIntercept = "TouchEventIntercept";
    std::string keyEventIntercept = "KeyEventIntercept";
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, onKeyEvent, keyId);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "service report keyId=" + std::to_string(keyId));
}

void BytraceAdapter::StartBytrace(std::shared_ptr<PointerEvent> pointerEvent, TraceBtn traceBtn)
{
    CHKPV(pointerEvent);
    int32_t eventId = pointerEvent->GetId();
    if (traceBtn == TRACE_START) {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, onPointerEvent, eventId);
            BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "service report pointerId:" + std::to_string(eventId));
        } else {
            StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, onTouchEvent, eventId);
            BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "service report touchId:" + std::to_string(eventId));
        }
    } else {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, onPointerEvent, eventId);
        } else {
            FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, onTouchEvent, eventId);
        }
    }
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> key, HandlerType handlerType)
{
    CHKPV(key);
    int32_t keyCode = key->GetKeyCode();
    std::string checkKeyCode;
    switch (handlerType) {
        case KEY_INTERCEPT_EVENT: {
            checkKeyCode = "Intercept keycode:" + std::to_string(keyCode);
            break;
        }
        case KEY_LAUNCH_EVENT: {
            checkKeyCode = "Launch keycode:" + std::to_string(keyCode);
            break;
        }
        case KEY_SUBSCRIBE_EVENT: {
            checkKeyCode = "Subscribe keycode:" + std::to_string(keyCode);
            break;
        }
        case KEY_DISPATCH_EVENT: {
            checkKeyCode = "Dispatch keycode:" + std::to_string(keyCode);
            break;
        }
        default: {
            checkKeyCode = "Unknow keycode:" + std::to_string(keyCode);
            break;
        }
    }
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, checkKeyCode);
    int32_t keyId = key->GetId();
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, onKeyEvent, keyId);
}

void BytraceAdapter::StartBytrace(std::shared_ptr<KeyEvent> keyEvent, TraceBtn traceBtn, HandlerType handlerType)
{
    CHKPV(keyEvent);
    int32_t keyId = keyEvent->GetId();
    int32_t keyCode = keyEvent->GetKeyCode();
    if (traceBtn == TRACE_START) {
        switch (handlerType) {
            case KEY_INTERCEPT_EVENT: {
                StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventIntercept, keyId);
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "client Intercept keyCode:" + std::to_string(keyCode));
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventSubscribe, keyId);
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "client subscribe keyCode:" + std::to_string(keyCode));
                break;
            }
            case KEY_DISPATCH_EVENT: {
                StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventDispatch, keyId);
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "client dispatch keyCode:" + std::to_string(keyCode));
                break;
            }
            default: {
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "Unknow keycode:" + std::to_string(keyCode));
                break;
            }
        }
    } else {
        switch (handlerType) {
            case KEY_INTERCEPT_EVENT: {
                FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventIntercept, keyId);
                break;
            }
            case KEY_SUBSCRIBE_EVENT: {
                FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventSubscribe, keyId);
                break;
            }
            case KEY_DISPATCH_EVENT: {
                FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventDispatch, keyId);
                break;
            }
            default: {
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "Unknow keycode:" + std::to_string(keyCode));
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
                StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventDispatch, eventId);
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "client dispatch pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEventDispatch, eventId);
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "client dispatch touchId:" + std::to_string(eventId));
            }
        } else {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventIntercept, eventId);
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "client Intercept pointerId:" + std::to_string(eventId));
            } else {
                StartAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEventIntercept, eventId);
                BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, "client Intercept touchId:" + std::to_string(eventId));
            }
        }
    } else {
        if (handlerType == POINT_DISPATCH_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventDispatch, eventId);
            } else {
                FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEventDispatch, eventId);
            }
        }
        if (handlerType == POINT_INTERCEPT_EVENT) {
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
                FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEventIntercept, eventId);
            } else {
                FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEventIntercept, eventId);
            }
        }
    }
}
} // namespace MMI
} // namespace OHOS