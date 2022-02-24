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

#include "server_input_filter_manager.h"
#include <cinttypes>
#include "input_event_data_transformation.h"
#include "mmi_server.h"
namespace OHOS {
namespace MMI {
namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ServerInputFilterManager" };
}

ServerInputFilterManager::KeyEventFilter::KeyEventFilter(int32_t id, std::string name,
    Authority authority) : id_(id), name_(name), authority_(authority)
{
}

ServerInputFilterManager::PointerEventFilter::PointerEventFilter(int32_t id, std::string name,
    Authority authority) : id_(id), name_(name), authority_(authority)
{
}

void ServerInputFilterManager::DeleteFilterFromSess(SessionPtr sess)
{
    CHKPV(sess);
    auto it = keyEventFilterMap_.find(sess);
    if (it == keyEventFilterMap_.end()) {
        MMI_LOGD("This sess have not any filter");
    } else {
        keyEventFilterMap_.erase(it);
        MMI_LOGD("This sess delete filter success");
    }
}

int32_t ServerInputFilterManager::KeyEventFilter::GetId()
{
    return id_;
}

std::string ServerInputFilterManager::KeyEventFilter::GetName()
{
    return name_;
}

Authority ServerInputFilterManager::KeyEventFilter::GetAuthority()
{
    return authority_;
}

void ServerInputFilterManager::KeyEventFilter::SetName(std::string name)
{
    name_ = name;
}

void ServerInputFilterManager::KeyEventFilter::SetId(int32_t id)
{
    id_ = id;
}

void ServerInputFilterManager::KeyEventFilter::SetAuthority(Authority authority)
{
    authority_ = authority;
}

bool ServerInputFilterManager::OnKeyEvent(const EventKeyboard& key)
{
    MMI_LOGD("Enter");
    if (keyEventFilterMap_.empty()) {
        MMI_LOGD("keyEventFilterMap_ is empty");
        return false;
    }
    SessionPtr temp;
    int32_t id = 0;
    Authority authorityTemp = NO_AUTHORITY;
    for (auto &item : keyEventFilterMap_) {
        if (item.second.GetAuthority() > authorityTemp) {
            authorityTemp = item.second.GetAuthority();
            temp = item.first;
            id = item.second.GetId();
        }
    }
    CHKPF(temp);
    if (id == 0) {
        MMI_LOGD("Send msg id is 0");
        return false;
    }
    NetPacket pkt(MmiMessageId::KEY_EVENT_INTERCEPTOR);
    pkt << key << id;
    if (!temp->SendMsg(pkt)) {
        MMI_LOGE("Sending structure of EventKeyboard failed");
        return false;
    }
    MMI_LOGD("Leave");
    return true;
}

int32_t ServerInputFilterManager::AddKeyEventFilter(SessionPtr sess, std::string name, int32_t id, Authority authority)
{
    auto  it = keyEventFilterMap_.find(sess);
    if (it == keyEventFilterMap_.end()) {
        MMI_LOGD("Can't find sess");
        KeyEventFilter keyEventFilter(id, name, authority);
        keyEventFilterMap_.insert(std::pair<SessionPtr, KeyEventFilter>(sess, keyEventFilter));
        MMI_LOGD("Add a key Event filter success");
    } else if (it->second.GetAuthority() < authority) {
        MMI_LOGD("Add a key Event filter success");
        it->second.SetAuthority(authority);
        it->second.SetId(id);
        it->second.SetName(name);
    }
    return RET_OK;
}

int32_t ServerInputFilterManager::RemoveKeyEventFilter(SessionPtr sess, int32_t id)
{
    auto it = keyEventFilterMap_.find(sess);
    MMI_LOGD("Remove the id:%{public}d", it->second.GetId());
    if (it != keyEventFilterMap_.end() && it->second.GetId() == id) {
        keyEventFilterMap_.erase(it);
        MMI_LOGD("Remove a key Event filter success");
    }
    return RET_OK;
}

ServerInputFilterManager::TouchEventFilter::TouchEventFilter(int32_t id, std::string name,
    Authority authority) : id_(id), name_(name), authority_(authority)
{
}

int32_t ServerInputFilterManager::TouchEventFilter::GetId()
{
    return id_;
}

std::string ServerInputFilterManager::TouchEventFilter::GetName()
{
    return name_;
}

Authority ServerInputFilterManager::TouchEventFilter::GetAuthority()
{
    return authority_;
}

void ServerInputFilterManager::TouchEventFilter::SetName(std::string name)
{
    name_ = name;
}

void ServerInputFilterManager::TouchEventFilter::SetId(int32_t id)
{
    id_ = id;
}

void ServerInputFilterManager::TouchEventFilter::SetAuthority(Authority authority)
{
    authority_ = authority;
}

void ServerInputFilterManager::OnEventTouchGetPointEventType(const EventTouch& touch,
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
                MMI_LOGW("Unknown event type of pointer, TouchPointType:%{public}d", touch.eventType);
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
                MMI_LOGW("Unknown event type of pointer, TouchPointType:%{public}d", touch.eventType);
                break;
            }
        }
    }
}

bool ServerInputFilterManager::OnTouchEvent(libinput_event *event,
    const EventTouch& touch, const uint64_t preHandlerTime)
{
    MMI_LOGD("Enter");
    CHKPF(event);
    if (touchEventFilterMap_.empty()) {
        MMI_LOGE("touchEventFilterMap_ is empty");
        return false;
    }
    SessionPtr temp;
    int32_t id = 0;
    Authority authorityTemp = NO_AUTHORITY;
    for (auto &item : touchEventFilterMap_) {
        if (item.second.GetAuthority() > authorityTemp) {
            authorityTemp = item.second.GetAuthority();
            temp = item.first;
            id = item.second.GetId();
        }
    }
    CHKPF(temp);
    if (id == 0) {
        MMI_LOGE("Send msg id is 0");
        return false;
    }

    auto device = libinput_event_get_device(event);
    CHKPF(device);

    MmiMessageId idMsg = MmiMessageId::INVALID;
    MMIRegEvent->OnEventTouchGetSign(touch, idMsg);

    int32_t touchFocusId = WinMgr->GetTouchFocusSurfaceId();
    auto appInfo = AppRegs->FindWinId(touchFocusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGE("Failed to find fd:%{public}d,errCode:%{public}d", touchFocusId, FOCUS_ID_OBTAIN_FAIL);
        return false;
    }
    MMI_LOGD("DispatchTouchEvent focusId:%{public}d,fd:%{public}d", touchFocusId, appInfo.fd);

    int32_t testConnectState = 0;
    int32_t testBufferState = 0;

    if (AppRegs->IsMultimodeInputReady(MmiMessageId::ON_TOUCH, appInfo.fd, touch.time)) {
        NetPacket newPacket(MmiMessageId::TOUCH_EVENT_INTERCEPTOR);
        int32_t fingerCount = MMIRegEvent->GetTouchInfoSizeDeviceId(touch.deviceId);
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            fingerCount++;
        }
        newPacket << fingerCount;
        POINT_EVENT_TYPE pointEventType = EVENT_TYPE_INVALID;
        OnEventTouchGetPointEventType(touch, fingerCount, pointEventType);
        int32_t eventType = pointEventType;
        newPacket << eventType << appInfo.abilityId << touchFocusId << appInfo.fd << preHandlerTime;

        std::vector<std::pair<uint32_t, int32_t>> touchIds;
        MMIRegEvent->GetTouchIds(touch.deviceId, touchIds);
        if (!touchIds.empty()) {
            for (std::pair<uint32_t, int32_t> touchId : touchIds) {
                EventTouch touchTemp = {};
                errno_t retErr = memcpy_s(&touchTemp, sizeof(touchTemp), &touch, sizeof(touch));
                CHKF(retErr == EOK, MEMCPY_SEC_FUN_FAIL);
                MMIRegEvent->GetTouchInfo(touchId, touchTemp);
                MMI_LOGD("4.event filter of server 1:eventTouch:time:%{public}" PRId64 ",deviceType:%{public}u,"
                         "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
                         "slot:%{public}d,seatSlot:%{public}d,pressure:%{public}lf,point.x:%{public}lf,"
                         "point.y:%{public}lf,fd:%{public}d,preHandlerTime:%{public}" PRId64,
                         touchTemp.time, touchTemp.deviceType, touchTemp.deviceName,
                         touchTemp.physical, touchTemp.eventType, touchTemp.slot, touchTemp.seatSlot,
                         touchTemp.pressure, touchTemp.point.x, touchTemp.point.y, appInfo.fd,
                         preHandlerTime);
                newPacket << touchTemp;
            }
        }
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            newPacket << touch;
            MMI_LOGD("4.event filter of server 2:eventTouch:time:%{public}" PRId64 ", deviceType:%{public}u,"
                     "deviceName:%{public}s,physical:%{public}s,eventType:%{public}d,"
                     "slot:%{public}d,seatSlot:%{public}d,pressure:%{public}lf,point.x:%{public}lf,"
                     "point.y:%{public}lf,fd:%{public}d,preHandlerTime:%{public}" PRId64,
                     touch.time, touch.deviceType, touch.deviceName,
                     touch.physical, touch.eventType, touch.slot, touch.seatSlot, touch.pressure,
                     touch.point.x, touch.point.y, appInfo.fd, preHandlerTime);
        }
        newPacket << id;
        if (!temp->SendMsg(newPacket)) {
            MMI_LOGE("Sending Interceptor EventTouch failed, session.fd:%{public}d", temp->GetFd());
            return false;
        }
    }
    MMI_LOGD("Leave");
    return true;
}

int32_t ServerInputFilterManager::AddTouchEventFilter(SessionPtr sess, std::string name, int32_t id,
    Authority authority)
{
    MMI_LOGE("Enter");
    auto iter = touchEventFilterMap_.find(sess);
    if (iter != touchEventFilterMap_.end()) {
        if (iter->second.GetAuthority() < authority) {
            iter->second.SetAuthority(authority);
            iter->second.SetId(id);
            iter->second.SetName(name);
        }
        MMI_LOGD("Replace a touch filter success");
        return RET_OK;
    }
    TouchEventFilter touchEventFilter(id, name, authority);
    touchEventFilterMap_.insert(std::pair<SessionPtr, TouchEventFilter>(sess, touchEventFilter));
    MMI_LOGE("Leave");
    return RET_OK;
}

int32_t ServerInputFilterManager::RemoveTouchEventFilter(SessionPtr sess, int32_t id)
{
    MMI_LOGE("Enter");
    auto iter = touchEventFilterMap_.find(sess);
    if (iter != touchEventFilterMap_.end() && iter->second.GetId() == id) {
        touchEventFilterMap_.erase(sess);
        MMI_LOGE("Remove a touch filter success");
    }
    MMI_LOGE("Leave");
    return RET_OK;
}

int32_t ServerInputFilterManager::RemoveTouchEventFilter(SessionPtr sess)
{
    MMI_LOGE("Enter");
    if (sess == nullptr) {
        MMI_LOGE("This sess is nullptr");
        return RET_ERR;
    }
    auto iter = touchEventFilterMap_.find(sess);
    if (iter != touchEventFilterMap_.end()) {
        touchEventFilterMap_.erase(sess);
        MMI_LOGE("This sess delete filter success");
    }
    MMI_LOGE("Leave");
    return RET_OK;
}

bool ServerInputFilterManager::OnPointerEvent(EventPointer event_pointer)
{
    MMI_LOGD("Enter");
    if (pointerEventFilterMap_.empty()) {
        MMI_LOGD("pointerEventFilterMap_ is empty");
        return false;
    }
    SessionPtr ptr;
    int32_t id;
    Authority authority = NO_AUTHORITY;
    for (auto &item : pointerEventFilterMap_) {
        if (item.second.GetAuthority() > authority) {
            ptr = item.first;
            id = item.second.GetId();
            authority = item.second.GetAuthority();
        }
    }
    CHKPF(ptr);
    if (id == 0) {
        MMI_LOGD("Send msg id is 0");
        return false;
    }
    NetPacket pkt(MmiMessageId::POINTER_EVENT_INTERCEPTOR);
    pkt << event_pointer << id;
    if (!ptr->SendMsg(pkt)) {
        MMI_LOGE("Sending structure of pointer failed");
        return false;
    }
    MMI_LOGD("Leave");
    return true;
}

int32_t ServerInputFilterManager::RegisterEventInterceptorforServer(const SessionPtr& sess, int32_t id,
                                                                    std::string name, Authority authority)
{
    auto it = pointerEventFilterMap_.find(sess);
    if (it == pointerEventFilterMap_.end()) {
        MMI_LOGD("Can't find sess");
        PointerEventFilter pointerEventFilter(id, name, authority);
        pointerEventFilterMap_.insert(std::pair<SessionPtr, PointerEventFilter>(sess, pointerEventFilter));
        MMI_LOGD("Add pointer event interceptor success");
    } else if (it->second.GetAuthority() < authority) {
        MMI_LOGD("Add pointer event interceptor success");
        it->second.SetAuthority(authority);
        it->second.SetId(id);
        it->second.SetName(name);
    }
    return RET_OK;
}

int32_t ServerInputFilterManager::UnregisterEventInterceptorforServer(const SessionPtr& sess, int32_t id)
{
    auto it = pointerEventFilterMap_.find(sess);
    MMI_LOGD("Remove the id:%{public}d", it->second.GetId());
    if (it != pointerEventFilterMap_.end() && it->second.GetId() == id) {
        pointerEventFilterMap_.erase(it);
        MMI_LOGD("Remove pointer Event interceptor success");
    }
    return RET_OK;
}

void ServerInputFilterManager::DeleteInterceptorFormSess(const SessionPtr& sess)
{
    CHKPV(sess);
    auto it = pointerEventFilterMap_.find(sess);
    if (it == pointerEventFilterMap_.end()) {
        MMI_LOGD("This sess have not any interceptor");
    } else {
        pointerEventFilterMap_.erase(it);
        MMI_LOGD("This interceptor deleted suceess");
    }
}

int32_t ServerInputFilterManager::PointerEventFilter::GetId()
{
    return id_;
}

std::string ServerInputFilterManager::PointerEventFilter::GetName()
{
    return name_;
}

Authority ServerInputFilterManager::PointerEventFilter::GetAuthority()
{
    return authority_;
}

void ServerInputFilterManager::PointerEventFilter::SetName(std::string name)
{
    name_ = name;
}

void ServerInputFilterManager::PointerEventFilter::SetId(int32_t id)
{
    id_ = id;
}

void ServerInputFilterManager::PointerEventFilter::SetAuthority(Authority authority)
{
    authority_ = authority;
}
} // namespace MMI
} // namespace OHOS