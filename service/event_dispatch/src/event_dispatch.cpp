/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_dispatch.h"
#include <cinttypes>
#include "ability_launch_manager.h"
#include "ability_manager_client.h"
#include "bytrace.h"
#include "event_filter_wrap.h"
#include "hisysevent.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "input_event_monitor_manager.h"
#include "input_handler_manager_global.h"
#include "input-event-codes.h"
#include "interceptor_manager_global.h"
#include "key_event_subscriber.h"
#include "system_event_handler.h"
#include "util.h"

namespace OHOS {
namespace MMI {
constexpr int64_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatch" };
}

EventDispatch::EventDispatch()
{
}

EventDispatch::~EventDispatch()
{
}

void EventDispatch::OnEventTouchGetPointEventType(const EventTouch& touch,
                                                  const int32_t fingerCount,
                                                  POINT_EVENT_TYPE& pointEventType)
{
    CHK(fingerCount > 0, PARAM_INPUT_INVALID);
    CHK(touch.time > 0, PARAM_INPUT_INVALID);
    CHK(touch.seatSlot >= 0, PARAM_INPUT_INVALID);
    CHK(touch.eventType >= 0, PARAM_INPUT_INVALID);
    if (fingerCount == 1) {
        switch (touch.eventType) {
            case LIBINPUT_EVENT_TOUCH_DOWN: {
                pointEventType = PRIMARY_POINT_DOWN;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_UP: {
                pointEventType = PRIMARY_POINT_UP;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_MOTION: {
                pointEventType = POINT_MOVE;
                break;
            }
            default: {
                break;
            }
        }
    } else {
        switch (touch.eventType) {
            case LIBINPUT_EVENT_TOUCH_DOWN: {
                pointEventType = OTHER_POINT_DOWN;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_UP: {
                pointEventType = OTHER_POINT_UP;
                break;
            }
            case LIBINPUT_EVENT_TOUCH_MOTION: {
                pointEventType = POINT_MOVE;
                break;
            }
            default: {
                break;
            }
        }
    }
}

bool EventDispatch::HandlePointerEventFilter(std::shared_ptr<PointerEvent> point)
{
    return EventFilterWrap::GetInstance().HandlePointerEventFilter(point);
}

void EventDispatch::HandlePointerEventTrace(const std::shared_ptr<PointerEvent> &point)
{
    if (point->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        int32_t pointerId = point->GetId();
        std::string pointerEvent = "OnEventPointer";
        FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEvent, pointerId);
    }
    if (point->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        int32_t touchId = point->GetId();
        std::string touchEvent = "OnEventTouch";
        FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, touchEvent, touchId);
    }
}

int32_t EventDispatch::HandlePointerEvent(std::shared_ptr<PointerEvent> point)
{
    CHKPR(point, ERROR_NULL_POINTER);
    auto fd = WinMgr->UpdateTargetPointer(point);
    if (HandlePointerEventFilter(point)) {
        MMI_LOGI("Pointer event interception succeeded");
        return RET_OK;
    }
    if (InputHandlerManagerGlobal::GetInstance().HandleEvent(point)) {
        HandlePointerEventTrace(point);
        return RET_OK;
    }
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(point, pkt);
    HandlePointerEventTrace(point);
    auto udsServer = InputHandler->GetUDSServer();
    if (udsServer == nullptr) {
        MMI_LOGE("UdsServer is a nullptr");
        return RET_ERR;
    }
    if (fd < 0) {
        MMI_LOGE("The fd less than 0");
        return RET_ERR;
    }

    auto session = udsServer->GetSession(fd);
    CHKPF(session);
    if (session->isANRProcess_) {
        MMI_LOGI("is ANR process");
        return RET_OK;
    }

    auto currentTime = GetSysClockTime();
    if (IsANRProcess(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_LOGE("the pointer event does not report normally, triggering ANR");
        return RET_OK;
    }

    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_LOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    session->AddEvent(point->GetId(), currentTime);
    return RET_OK;
}

void EventDispatch::OnKeyboardEventTrace(const std::shared_ptr<KeyEvent> &key, IsEventHandler isEventHandler)
{
    MMI_LOGD("enter");
    int32_t keyCode = key->GetKeyCode();
    std::string checkKeyCode;
    if (isEventHandler == KEY_FILTER_EVENT) {
        checkKeyCode = "key intercept service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("key intercept service trace GetKeyCode:%{public}d", keyCode);
    } else if (isEventHandler == KEY_CHECKLAUNABILITY_EVENT) {
        checkKeyCode = "CheckLaunchAbility service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("CheckLaunchAbility service trace GetKeyCode:%{public}d", keyCode);
    } else if (isEventHandler == KEY_SUBSCRIBE_EVENT) {
        checkKeyCode = "SubscribeKeyEvent service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("SubscribeKeyEvent service trace GetKeyCode:%{public}d", keyCode);
    } else {
        checkKeyCode = "DispatchKeyEvent service GetKeyCode=" + std::to_string(keyCode);
        MMI_LOGD("DispatchKeyEvent service trace GetKeyCode:%{public}d", keyCode);
    }
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, checkKeyCode);
    int32_t keyId = key->GetId();
    const std::string keyEventString = "OnKeyEvent";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
}

int32_t EventDispatch::DispatchKeyEventPid(UDSServer& udsServer,
    std::shared_ptr<KeyEvent> key, const int64_t preHandlerTime)
{
    MMI_LOGD("begin");
    CHKPR(key, PARAM_INPUT_INVALID);
    if (!key->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        if (InterceptorMgrGbl.OnKeyEvent(key)) {
            MMI_LOGD("keyEvent filter find a keyEvent from Original event keyCode: %{puiblic}d",
                key->GetKeyCode());
            OnKeyboardEventTrace(key, KEY_FILTER_EVENT);
            return RET_OK;
        }
    }
    if (AbilityMgr->CheckLaunchAbility(key)) {
        MMI_LOGD("The keyEvent start launch an ability, keyCode:%{public}d", key->GetKeyCode());
        OnKeyboardEventTrace(key, KEY_CHECKLAUNABILITY_EVENT);
        return RET_OK;
    }
    if (KeyEventSubscriber_.SubscribeKeyEvent(key)) {
        MMI_LOGD("Subscribe keyEvent filter success. keyCode:%{public}d", key->GetKeyCode());
        OnKeyboardEventTrace(key, KEY_SUBSCRIBE_EVENT);
        return RET_OK;
    }
    auto fd = WinMgr->UpdateTarget(key);
    CHKR(fd >= 0, FD_OBTAIN_FAIL, RET_ERR);

    MMI_LOGD("4.event dispatcher of server:KeyEvent:KeyCode:%{public}d,"
             "ActionTime:%{public}" PRId64 ",Action:%{public}d,ActionStartTime:%{public}" PRId64 ","
             "EventType:%{public}d,Flag:%{public}u,"
             "KeyAction:%{public}d,Fd:%{public}d,PreHandlerTime:%{public}" PRId64 "",
             key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
             key->GetActionStartTime(),
             key->GetEventType(),
             key->GetFlag(), key->GetKeyAction(), fd, preHandlerTime);

    InputHandlerManagerGlobal::GetInstance().HandleEvent(key);
    auto session = udsServer.GetSession(fd);
    CHKPF(session);
    if (session->isANRProcess_) {
        MMI_LOGI("is ANR process");
        return RET_OK;
    }

    auto currentTime = GetSysClockTime();
    if (IsANRProcess(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_LOGE("the key event does not report normally, triggering ANR");
        return RET_OK;
    }

    NetPacket pkt(MmiMessageId::ON_KEYEVENT);
    InputEventDataTransformation::KeyEventToNetPacket(key, pkt);
    OnKeyboardEventTrace(key, KEY_DISPATCH_EVENT);
    pkt << fd << preHandlerTime;
    if (!udsServer.SendMsg(fd, pkt)) {
        MMI_LOGE("Sending structure of EventKeyboard failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    session->AddEvent(key->GetId(), currentTime);
    MMI_LOGD("end");
    return RET_OK;
}

int32_t EventDispatch::AddInputEventFilter(sptr<IEventFilter> filter)
{
    return EventFilterWrap::GetInstance().AddInputEventFilter(filter);
}

bool EventDispatch::IsANRProcess(int64_t time, SessionPtr ss)
{
    MMI_LOGD("begin");
    int64_t firstTime;
    if (ss->EventsIsEmpty()) {
        firstTime = time;
    } else {
        firstTime = ss->GetFirstEventTime();
    }

    if (time < (firstTime + INPUT_UI_TIMEOUT_TIME)) {
        ss->isANRProcess_ = false;
        MMI_LOGI("the event reports normally");
        return false;
    }

    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPLICATION_BLOCK_INPUT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PID", ss->GetPid(),
        "UID", ss->GetUid(),
        "PACKAGE_NAME", "",
        "PROCESS_NAME", "",
        "MSG", "failed to dispatch pointer or key events of multimodalinput");
    if (ret != 0) {
        MMI_LOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }

    ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->SendANRProcessID(ss->GetPid());
    if (ret != 0) {
        MMI_LOGE("AAFwk SendANRProcessID failed, AAFwk errCode: %{public}d", ret);
    }
    MMI_LOGD("end");
    return true;
}
} // namespace MMI
} // namespace OHOS