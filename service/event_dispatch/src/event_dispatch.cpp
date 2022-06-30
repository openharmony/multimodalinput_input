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

#include "ability_manager_client.h"
#include "hitrace_meter.h"
#include "input-event-codes.h"
#include "hisysevent.h"

#include "bytrace_adapter.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatch" };
constexpr int64_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
} // namespace

EventDispatch::EventDispatch() {}

EventDispatch::~EventDispatch() {}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventDispatch::HandleKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    DispatchKeyEventPid(*udsServer, keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventDispatch::HandleTouchEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

void EventDispatch::OnEventTouchGetPointEventType(const EventTouch& touch,
                                                  const int32_t fingerCount,
                                                  POINT_EVENT_TYPE& pointEventType)
{
    if (fingerCount <= 0 || touch.time <= 0 || touch.seatSlot < 0 || touch.eventType < 0) {
        MMI_HILOGE("The in parameter is error, fingerCount:%{public}d, touch.time:%{public}" PRId64 ","
                   "touch.seatSlot:%{public}d, touch.eventType:%{public}d",
                   fingerCount, touch.time, touch.seatSlot, touch.eventType);
        return;
    }
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

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void EventDispatch::HandlePointerEvent(std::shared_ptr<PointerEvent> point)
{
    CALL_LOG_ENTER;
    CHKPV(point);
    auto fd = WinMgr->UpdateTargetPointer(point);
    if (fd < 0) {
        MMI_HILOGE("The fd less than 0, fd: %{public}d", fd);
        return;
    }
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto session = udsServer->GetSession(fd);
    CHKPV(session);
    if (session->isANRProcess_) {
        MMI_HILOGD("application not responding");
        return;
    }
    auto currentTime = GetSysClockTime();
    if (TriggerANR(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_HILOGW("the pointer event does not report normally, application not response");
        return;
    }

    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(point, pkt);
    BytraceAdapter::StartBytrace(point, BytraceAdapter::TRACE_STOP);
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
    session->AddEvent(point->GetId(), currentTime);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t EventDispatch::DispatchKeyEventPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key)
{
    CALL_LOG_ENTER;
    CHKPR(key, PARAM_INPUT_INVALID);
    auto fd = WinMgr->UpdateTarget(key);
    if (fd < 0) {
        MMI_HILOGE("Invalid fd, fd: %{public}d", fd);
        return RET_ERR;
    }
    MMI_HILOGD("event dispatcher of server:KeyEvent:KeyCode:%{public}d,"
               "ActionTime:%{public}" PRId64 ",Action:%{public}d,ActionStartTime:%{public}" PRId64 ","
               "EventType:%{public}d,Flag:%{public}u,"
               "KeyAction:%{public}d,Fd:%{public}d",
               key->GetKeyCode(), key->GetActionTime(), key->GetAction(),
               key->GetActionStartTime(),
               key->GetEventType(),
               key->GetFlag(), key->GetKeyAction(), fd);
    auto session = udsServer.GetSession(fd);
    CHKPR(session, RET_ERR);
    if (session->isANRProcess_) {
        MMI_HILOGD("application not responding");
        return RET_OK;
    }
    auto currentTime = GetSysClockTime();
    if (TriggerANR(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_HILOGW("the key event does not report normally, application not response");
        return RET_OK;
    }

    NetPacket pkt(MmiMessageId::ON_KEYEVENT);
    InputEventDataTransformation::KeyEventToNetPacket(key, pkt);
    BytraceAdapter::StartBytrace(key, BytraceAdapter::KEY_DISPATCH_EVENT);
    pkt << fd;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write structure of EventKeyboard failed");
        return RET_ERR;
    }
    if (!udsServer.SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventKeyboard failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    session->AddEvent(key->GetId(), currentTime);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

bool EventDispatch::TriggerANR(int64_t time, SessionPtr sess)
{
    CALL_LOG_ENTER;
    int64_t earliest;
    if (sess->IsEventQueueEmpty()) {
        earliest = time;
    } else {
        earliest = sess->GetEarliestEventTime();
    }
    MMI_HILOGD("Current time: %{public}" PRId64 "", time);
    if (time < (earliest + INPUT_UI_TIMEOUT_TIME)) {
        sess->isANRProcess_ = false;
        MMI_HILOGD("the event reports normally");
        return false;
    }

    int32_t ret = OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "APPLICATION_BLOCK_INPUT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PID", sess->GetPid(),
        "UID", sess->GetUid(),
        "PACKAGE_NAME", "",
        "PROCESS_NAME", "",
        "MSG", "User input does not respond");
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, HiviewDFX errCode: %{public}d", ret);
    }

    ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->SendANRProcessID(sess->GetPid());
    if (ret != 0) {
        MMI_HILOGE("AAFwk SendANRProcessID failed, AAFwk errCode: %{public}d", ret);
    }
    MMI_HILOGI("AAFwk send ANR process id succeeded");
    return true;
}
} // namespace MMI
} // namespace OHOS
