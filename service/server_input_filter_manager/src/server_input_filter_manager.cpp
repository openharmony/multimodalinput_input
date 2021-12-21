/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "mmi_server.h"

namespace OHOS::MMI {
namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ServerInputFilterManager" };
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
    if (sess == nullptr) {
        MMI_LOGD("this sess is nullptr");
        return;
    }
    auto it = keyEventFilterMap_.find(sess);
    if (it == keyEventFilterMap_.end()) {
        MMI_LOGD("this sess have not any filter");
    } else {
        keyEventFilterMap_.erase(it);
        MMI_LOGD("this sess delete filter success");
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
    this->name_ = name;
}

void ServerInputFilterManager::KeyEventFilter::SetId(int32_t id)
{
    this->id_ = id;
}

void ServerInputFilterManager::KeyEventFilter::SetAuthority(Authority authority)
{
    this->authority_ = authority;
}

bool ServerInputFilterManager::OnKeyEvent(EventKeyboard key)
{
    MMI_LOGD("key event filter on key event begin");
    if (keyEventFilterMap_.size() == 0) {
        MMI_LOGD("keyEventFilterMap_ size is zero");
        return false;
    }
    SessionPtr temp;
    int32_t id = 0;
    Authority authorityTemp = NO_AUTHORITY;
    for (auto item : keyEventFilterMap_) {
        if (item.second.GetAuthority() > authorityTemp) {
            authorityTemp = item.second.GetAuthority();
            temp = item.first;
            id = item.second.GetId();
        }
    }
    if (temp == nullptr) {
        MMI_LOGD("session  is nullptr");
        return false;
    }
    if (id == 0) {
        MMI_LOGD("send msg  id is 0");
        return false;
    }
    NetPacket newPkt(MmiMessageId::KEY_EVENT_INTERCEPTOR);
    newPkt << key <<id;
    if (!temp->SendMsg(newPkt)) {
        MMI_LOGE("Sending structure of EventKeyboard failed! \n");
        return false;
    }
    MMI_LOGD("key event filter on key event end");
    return true;
}

int32_t ServerInputFilterManager::AddKeyEventFilter(SessionPtr sess, std::string name, int32_t id, Authority authority)
{
    auto  it = keyEventFilterMap_.find(sess);
    if (it == keyEventFilterMap_.end()) {
        MMI_LOGD("can't find sess");
        KeyEventFilter keyEventFilter(id, name, authority);
        keyEventFilterMap_.insert(std::pair<SessionPtr, KeyEventFilter>(sess, keyEventFilter));
        MMI_LOGD("add a key Event filter success");
    } else if (it->second.GetAuthority() < authority) {
        MMI_LOGD("add a key Event filter success");
        it->second.SetAuthority(authority);
        it->second.SetId(id);
        it->second.SetName(name);
    }
    return RET_OK;
}

int32_t ServerInputFilterManager::RemoveKeyEventFilter(SessionPtr sess, int32_t id)
{
    auto it = keyEventFilterMap_.find(sess);
    MMI_LOGD("remove  the  id : %{public}d", it->second.GetId());
    if (it != keyEventFilterMap_.end() && it->second.GetId() == id) {
        keyEventFilterMap_.erase(it);
        MMI_LOGD("remove a key Event filter success");
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
    this->name_ = name;
}

void ServerInputFilterManager::TouchEventFilter::SetId(int32_t id)
{
    this->id_ = id;
}

void ServerInputFilterManager::TouchEventFilter::SetAuthority(Authority authority)
{
    this->authority_ = authority;
}

void ServerInputFilterManager::OnEventTouchGetPointEventType(const EventTouch& touch,
    POINT_EVENT_TYPE& pointEventType, const int32_t fingerCount)
{
    CHK(fingerCount > 0, PARAM_INPUT_INVALID);
    CHK(touch.time > 0, PARAM_INPUT_INVALID);
    CHK(touch.seat_slot >= 0, PARAM_INPUT_INVALID);
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

bool ServerInputFilterManager::OnTouchEvent(UDSServer& udsServer, libinput_event& event,
    EventTouch& touch, const uint64_t preHandlerTime, WindowSwitch& windowSwitch)
{
    MMI_LOGD("ServerInputFilterManager::OnTouchEvent");
    if (touchEventFilterMap_.size() == 0) {
        MMI_LOGD("touchEventFilterMap_ size is zero");
        return false;
    }
    SessionPtr temp;
    int32_t id = 0;
    Authority authorityTemp = NO_AUTHORITY;
    for (auto item : touchEventFilterMap_) {
        if (item.second.GetAuthority() > authorityTemp) {
            authorityTemp = item.second.GetAuthority();
            temp = item.first;
            id = item.second.GetId();
        }
    }
    if (temp == nullptr) {
        MMI_LOGD("session  is nullptr");
        return false;
    }
    if (id == 0) {
        MMI_LOGD("send msg  id is 0");
        return false;
    }

    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);

    MmiMessageId idMsg = MmiMessageId::INVALID;
    MMIRegEvent->OnEventTouchGetSign(touch, idMsg);

    int32_t touchFocusId = WinMgr->GetTouchFocusSurfaceId();
    auto appInfo = AppRegs->FindByWinId(touchFocusId); // obtain application information
    if (appInfo.fd == RET_ERR) {
        MMI_LOGT("Failed to find fd:%{public}d... errCode:%{public}d", touchFocusId, FOCUS_ID_OBTAIN_FAIL);
        return false;
    }
    MMI_LOGD("DispatchTouchEvent focusId:%{public}d fd:%{public}d", touchFocusId, appInfo.fd);

    int32_t testConnectState = 0;
    int32_t testBufferState = 0;

    if (AppRegs->IsMultimodeInputReady(touch.time, MmiMessageId::ON_TOUCH, appInfo.fd, testConnectState,
        testBufferState)) {
        NetPacket newPacket(MmiMessageId::TOUCH_EVENT_INTERCEPTOR);
        int32_t fingerCount = MMIRegEvent->GetTouchInfoSizeByDeviceId(touch.deviceId);
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            fingerCount++;
        }
        newPacket << fingerCount;
        POINT_EVENT_TYPE pointEventType = EVENT_TYPE_INVALID;
        OnEventTouchGetPointEventType(touch, pointEventType, fingerCount);
        int32_t eventType = pointEventType;
        newPacket << eventType << appInfo.abilityId << touchFocusId << appInfo.fd << preHandlerTime;

        std::vector<PAIR<uint32_t, int32_t>> touchIds;
        MMIRegEvent->GetTouchIds(touchIds, touch.deviceId);
        if (!touchIds.empty()) {
            for (PAIR<uint32_t, int32_t> touchId : touchIds) {
                struct EventTouch touchTemp = {};
                CHKR(EOK == memcpy_s(&touchTemp, sizeof(touchTemp), &touch, sizeof(touch)),
                     MEMCPY_SEC_FUN_FAIL, RET_ERR);
                MMIRegEvent->GetTouchInfoByTouchId(touchTemp, touchId);
                MMI_LOGT("\n4.event filter of server 1:\neventTouch:time=%{public}" PRId64 ";deviceType=%{public}u;"
                         "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                         "slot=%{public}d;seat_slot=%{public}d;pressure=%{public}lf;point.x=%{public}lf;"
                         "point.y=%{public}lf;fd=%{public}d;"
                         "preHandlerTime=%{public}" PRId64";\n**************************************************\n",
                         touchTemp.time, touchTemp.deviceType, touchTemp.deviceName,
                         touchTemp.devicePhys, touchTemp.eventType, touchTemp.slot, touchTemp.seat_slot,
                         touchTemp.pressure, touchTemp.point.x, touchTemp.point.y, appInfo.fd,
                         preHandlerTime);
                newPacket << touchTemp;
            }
        }
        if (touch.eventType == LIBINPUT_EVENT_TOUCH_UP) {
            newPacket << touch;
            MMI_LOGT("\n4.event filter of server 2:\neventTouch:time=%{public}" PRId64 ";deviceType=%{public}u;"
                     "deviceName=%{public}s;devicePhys=%{public}s;eventType=%{public}d;"
                     "slot=%{public}d;seat_slot=%{public}d;pressure=%{public}lf;point.x=%{public}lf;"
                     "point.y=%{public}lf;fd=%{public}d;"
                     "preHandlerTime=%{public}" PRId64";\n*******************************************************\n",
                     touch.time, touch.deviceType, touch.deviceName,
                     touch.devicePhys, touch.eventType, touch.slot, touch.seat_slot, touch.pressure,
                     touch.point.x, touch.point.y, appInfo.fd, preHandlerTime);
        }
        newPacket << id;
        if (!temp->SendMsg(newPacket)) {
            MMI_LOGE("Sending Interceptor EventTouch failed!: session.fd = %{public}d \n", temp->GetFd());
            return false;
        }
    }
    return true;
}

int32_t ServerInputFilterManager::AddTouchEventFilter(SessionPtr sess, std::string name, int32_t id,
    Authority authority)
{
    MMI_LOGE("ServerInputFilterManager::AddTouchEventFilter");
    auto iter = touchEventFilterMap_.find(sess);
    if (iter != touchEventFilterMap_.end()) {
        if (iter->second.GetAuthority() < authority) {
            iter->second.SetAuthority(authority);
            iter->second.SetId(id);
            iter->second.SetName(name);
        }
        MMI_LOGT("replace a touch filter success");
        return RET_OK;
    }
    TouchEventFilter touchEventFilter(id, name, authority);
    touchEventFilterMap_.insert(std::pair<SessionPtr, TouchEventFilter>(sess, touchEventFilter));
    MMI_LOGE("add a touch filter success");
    return RET_OK;
}

int32_t ServerInputFilterManager::RemoveTouchEventFilter(SessionPtr sess, int32_t id)
{
    MMI_LOGE("ServerInputFilterManager::RemoveTouchEventFilter");
    auto iter = touchEventFilterMap_.find(sess);
    if (iter != touchEventFilterMap_.end() && iter->second.GetId() == id) {
        touchEventFilterMap_.erase(sess);
        MMI_LOGE("Remove a touch filter success");
    }
    return RET_OK;
}

int32_t ServerInputFilterManager::RemoveTouchEventFilter(SessionPtr sess)
{
    if (sess == nullptr) {
        MMI_LOGE("this sess is nullptr");
        return RET_ERR;
    }
    auto iter = touchEventFilterMap_.find(sess);
    if (iter != touchEventFilterMap_.end()) {
        touchEventFilterMap_.erase(sess);
        MMI_LOGE("this sess delete filter success");
    }
    return RET_OK;
}

bool ServerInputFilterManager::OnPointerEvent(EventPointer event_pointer)
{
    MMI_LOGD("pointer event filter on pointer event begin");
    if (pointerEventFilterMap_.size() == 0) {
        MMI_LOGD("pointerEventFilterMap_ size is zero");
        return false;
    }
    SessionPtr ptr;
    int32_t id;
    Authority authority = NO_AUTHORITY;
    for (auto item : pointerEventFilterMap_) {
        if (item.second.GetAuthority() > authority) {
            ptr = item.first;
            id = item.second.GetId();
            authority = item.second.GetAuthority();
        }
    }
    if (ptr == nullptr) {
        MMI_LOGD("session is nullptr");
        return false;
    }
    if (id == 0) {
        MMI_LOGD("send msg  id is 0");
        return false;
    }
    NetPacket newPkt(MmiMessageId::POINTER_EVENT_INTERCEPTOR);
    newPkt << event_pointer << id;
    if (!ptr->SendMsg(newPkt)) {
        MMI_LOGE("Sending structure of pointer failed! \n");
        return false;
    }
    MMI_LOGD("pointer event interceptor on pointer event end");
    return true;
}

int32_t ServerInputFilterManager::RegisterEventInterceptorforServer(const SessionPtr& sess, int32_t id,
                                                                    std::string name, Authority authority)
{
    auto it = pointerEventFilterMap_.find(sess);
    if (it == pointerEventFilterMap_.end()) {
        MMI_LOGD("can't find sess");
        PointerEventFilter pointerEventFilter(id, name, authority);
        pointerEventFilterMap_.insert(std::pair<SessionPtr, PointerEventFilter>(sess, pointerEventFilter));
        MMI_LOGD("add pointer event interceptor success");
    } else if (it->second.GetAuthority() < authority) {
        MMI_LOGD("add pointer event interceptor success");
        it->second.SetAuthority(authority);
        it->second.SetId(id);
        it->second.SetName(name);
    }
    return RET_OK;
}

int32_t ServerInputFilterManager::UnregisterEventInterceptorforServer(const SessionPtr& sess, int32_t id)
{
    auto it = pointerEventFilterMap_.find(sess);
    MMI_LOGD("remove  the  id : %{public}d", it->second.GetId());
    if (it != pointerEventFilterMap_.end() && it->second.GetId() == id) {
        pointerEventFilterMap_.erase(it);
        MMI_LOGD("remove pointer Event interceptor success");
    }
    return RET_OK;
}

void ServerInputFilterManager::DeleteInterceptorFormSess(const SessionPtr& sess)
{
    if (sess == nullptr) {
        MMI_LOGD("This SessionPtr is nullptr");
        return;
    }
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
    return this->id_;
}

std::string ServerInputFilterManager::PointerEventFilter::GetName()
{
    return this->name_;
}

Authority ServerInputFilterManager::PointerEventFilter::GetAuthority()
{
    return this->authority_;
}

void ServerInputFilterManager::PointerEventFilter::SetName(std::string name)
{
    this->name_ = name;
}

void ServerInputFilterManager::PointerEventFilter::SetId(int32_t id)
{
    this->id_ = id;
}

void ServerInputFilterManager::PointerEventFilter::SetAuthority(Authority authority)
{
    this->authority_ = authority;
}
}