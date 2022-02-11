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

#include "input_filter_manager.h"
#include "bytrace.h"
#include "log.h"
#include "mmi_client.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputFilterManager" };
}

int32_t InputFilterManager::idManager_ = 0;
int32_t InputFilterManager::FilterKeyEvent(std::string name, Authority authority,
    std::function<void(KeyBoardEvent)> handler)
{
    if (handler == nullptr) {
        MMI_LOGD("the input name or handle is nullptr");
        return RET_ERR;
    }
    MMI_LOGD("******************* the authority is %{public}d", authority);
    if (authority < NO_AUTHORITY || authority > HIGH_AUTHORITY) {
        MMI_LOGD("the input authority is incorrect");
        return RET_ERR;
    }
    KeyEventFilter keyEventFilter(name, authority, handler);
    keyEventFilterList_.push_back(keyEventFilter);
    if (authority > highestAuthority_) {
        MMI_LOGD("add filter is  the highest Authority");
        highestId_ = keyEventFilter.GetId();
        highestAuthority_ = authority;
        MMIEventHdl.AddKeyEventFIlter(keyEventFilter.GetId(), name, authority);
    }
    return RET_OK;
}

int32_t InputFilterManager::UnFilterKeyEvent(int32_t id)
{
    auto len = keyEventFilterList_.size();
    if (len == 0) {
        MMI_LOGD("  keyEventFilterList_ size is zero ");
        return RET_ERR;
    }
    for (auto it = keyEventFilterList_.begin(); it != keyEventFilterList_.end(); it++) {
        if (it->GetId() == id) {
            keyEventFilterList_.erase(it);
            if (id == highestId_) {
                MMIEventHdl.RemoveKeyEventFIlter(id);
                highestAuthority_ = NO_AUTHORITY;
                highestId_ = 0;
                break;
            }
            MMI_LOGD("remove filter isn't  the highest Authority");
            return RET_OK;
        }
    }
    if (len == keyEventFilterList_.size()) {
        MMI_LOGD("can't find this id");
        return RET_ERR;
    }
    if (keyEventFilterList_.empty()) {
        MMI_LOGD("remove filter is the last filter");
        return RET_OK;
    }
    auto item = keyEventFilterList_.begin();
    for (auto it = keyEventFilterList_.begin(); it != keyEventFilterList_.end(); it++) {
        if (it->GetAuthority() > highestAuthority_) {
            highestAuthority_ = it->GetAuthority();
            highestId_ = it->GetId();
            item = it;
        }
    }
    if (highestId_ != 0) {
        MMI_LOGD("after remove the highest filter, add a next highest filter ");
        MMIEventHdl.AddKeyEventFIlter(item->GetId(), item->GetName(), item->GetAuthority());
    }
    return RET_OK;
}

InputFilterManager::KeyEventFilter::KeyEventFilter(std::string name, Authority authority,
    std::function<void(KeyBoardEvent)> handler) : name_(name), authority_(authority), handler_(handler)
{
    idManager_++;
    id_ = idManager_;
}

void InputFilterManager::KeyEventFilter::SetId(int32_t id)
{
    id_ = id;
}

int32_t InputFilterManager::KeyEventFilter::GetId()
{
    return id_;
}

std::string InputFilterManager::KeyEventFilter::GetName()
{
    return name_;
}
Authority InputFilterManager::KeyEventFilter::GetAuthority()
{
    return authority_;
}

std::function<void(KeyBoardEvent)> InputFilterManager::KeyEventFilter::GetHandler()
{
    return handler_;
}

void InputFilterManager::OnkeyEventTrace(const KeyBoardEvent& event)
{
    std::string keyEvent = "client keyUuid = " + event.GetUuid();
    char *tmpKey = (char*)keyEvent.c_str();
    MMI_LOGT(" OnKey keyUuid = %{public}s", tmpKey);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, keyEvent);
    int32_t eventKey = 4;
    keyEvent = "keyEventFilterAsync";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEvent, eventKey);
}

int32_t InputFilterManager::OnKeyEvent(KeyBoardEvent event, int32_t id)
{
    MMI_LOGD("client on key event call function handler ");
    OnkeyEventTrace(event);
    for (auto &item : keyEventFilterList_) {
        if (id == item.GetId()) {
            item.GetHandler()(event);
            MMI_LOGD("client on key event call function handler success");
            break;
        }
    }
    return 0;
}

int32_t InputFilterManager::GetHighAuthorityFilterId()
{
    Authority authority = NO_AUTHORITY;
    int32_t id = 0;
    for (auto &item : touchEventFilterList_) {
        if (item.GetAuthority() > authority) {
            authority = item.GetAuthority();
            id = item.GetId();
            if (authority == HIGH_AUTHORITY) {
                break;
            }
        }
    }
    return id;
}

InputFilterManager::TouchEventFilter InputFilterManager::GetTouchEventFilter(int32_t id)
{
    for (auto &item : touchEventFilterList_) {
        if (item.GetId() == id) {
            return item;
        }
    }
    InputFilterManager::TouchEventFilter touchEventFilter;
    touchEventFilter.SetId(0);
    return touchEventFilter;
}

int32_t InputFilterManager::FilterTouchEvent(std::string name, Authority authority,
    std::function<void(TouchEvent)> handler)
{
    if (handler == nullptr) {
        MMI_LOGE("the input name or handle is nullptr");
        return RET_ERR;
    }

    if (authority < NO_AUTHORITY || authority > HIGH_AUTHORITY) {
        MMI_LOGE("the input authority is incorrect");
        return RET_ERR;
    }

    TouchEventFilter touchEventFilter(name, authority, handler);
    touchEventFilterList_.push_back(touchEventFilter);

    int32_t highAuthorityFilterId = GetHighAuthorityFilterId();
    if (highAuthorityFilterId != 0 && highAuthorityFilterId == touchEventFilter.GetId()) {
        MMI_LOGE("add filter is  the highest Authority");
        MMIEventHdl.AddTouchEventFilter(touchEventFilter.GetId(), name, authority);
    }

    return touchEventFilter.GetId();
}

int32_t InputFilterManager::UnFilterTouchEvent(int32_t id)
{
    auto len = touchEventFilterList_.size();
    if (len == 0) {
        MMI_LOGE(" touchEventFilterList_ size is zero ");
        return RET_ERR;
    }

    int32_t highAuthorityFilterId = GetHighAuthorityFilterId();
    for (auto it = touchEventFilterList_.begin(); it != touchEventFilterList_.end(); it++) {
        if (it->GetId() == id) {
            MMI_LOGD("remove client filter success");
            touchEventFilterList_.erase(it);
            break;
        }
    }

    if (len == touchEventFilterList_.size()) {
        MMI_LOGE("can't find this id");
        return RET_ERR;
    }

    if (id == highAuthorityFilterId && highAuthorityFilterId != 0) {
        MMIEventHdl.RemoveTouchEventFilter(id);

        highAuthorityFilterId = GetHighAuthorityFilterId();
        if (highAuthorityFilterId != 0) {
            TouchEventFilter newFilter = GetTouchEventFilter(highAuthorityFilterId);
            if (newFilter.GetId() != 0) {
                MMI_LOGD("after remove the highest filter, add a next highest filter");
                MMIEventHdl.AddTouchEventFilter(newFilter.GetId(), newFilter.GetName(), newFilter.GetAuthority());
            }
        }
    } else {
        MMI_LOGD("remove filter isn't  the highest Authority");
    }

    return RET_OK;
}

InputFilterManager::TouchEventFilter::TouchEventFilter(std::string name, Authority authority,
    std::function<void(TouchEvent)> handler) : name_(name), authority_(authority), handler_(handler)
{
    idManager_++;
    id_ = idManager_;
}

void InputFilterManager::TouchEventFilter::SetId(int32_t id)
{
    id_ = id;
}

int32_t InputFilterManager::TouchEventFilter::GetId()
{
    return id_;
}

std::string InputFilterManager::TouchEventFilter::GetName()
{
    return name_;
}
Authority InputFilterManager::TouchEventFilter::GetAuthority()
{
    return authority_;
}

std::function<void(TouchEvent)> InputFilterManager::TouchEventFilter::GetHandler()
{
    return handler_;
}

int32_t InputFilterManager::OnTouchEvent(TouchEvent event, int32_t id)
{
    MMI_LOGE("client on touch event call function handler, id=%{public}d", id);
    for (auto iter : touchEventFilterList_) {
        if (id == iter.GetId()) {
            iter.GetHandler()(event);
            MMI_LOGE("client on touch event call function handler success");
            break;
        }
    }
    return RET_OK;
}

int32_t InputFilterManager::RegisterPointerEventInterceptor(std::string name_, Authority authority_,
                                                            std::function<void(MouseEvent)> handler_)
{
    if (handler_ == nullptr) {
        MMI_LOGD("the input name or handle is nullptr");
        return RET_ERR;
    }
    MMI_LOGD("******************* the authority is %{public}d", authority_);
    if (authority_ < NO_AUTHORITY || authority_ > HIGH_AUTHORITY) {
        MMI_LOGD("the input authority is incorrect");
        return RET_ERR;
    }
    PointerEventInterceptor pointer_interceptor(name_, authority_, handler_);
    PointerEventInterceptorList_.push_back(pointer_interceptor);
    if (authority_ > pHighestAuthority_) {
        MMI_LOGD("add filter is the highest Authority");
        pHighestId_ = pointer_interceptor.GetId();
        pHighestAuthority_ = authority_;
        MMIEventHdl.AddEventInterceptor(pointer_interceptor.GetId(), pointer_interceptor.GetName(),
                                        pointer_interceptor.GetAuthority());
    }
    return RET_OK;
}

int32_t InputFilterManager::UnRegisterPointerEventInterceptor(int32_t id_)
{
    auto len = PointerEventInterceptorList_.size();
    if (len == 0) {
        MMI_LOGD("The number of [pointer event interceptors] is 0");
        return RET_OK;
    }
    for (auto it = PointerEventInterceptorList_.begin(); it != PointerEventInterceptorList_.end(); it++) {
        if (it->GetId() == id_) {
            PointerEventInterceptorList_.erase(it);
            if (id_ == pHighestId_) {
                MMIEventHdl.RemoveEventInterceptor(id_);
                pHighestAuthority_ = NO_AUTHORITY;
                pHighestId_ = 0;
                break;
            }
            MMI_LOGD("remove pointer event interceptor isn't  the highest Authority");
            return RET_OK;
        }
    }
    if (len == PointerEventInterceptorList_.size()) {
        MMI_LOGD("can't find this id");
        return RET_ERR;
    }
    if (PointerEventInterceptorList_.size() == 0) {
        MMI_LOGD("remove pointer event interceptor is the last interceptor");
        return RET_OK;
    }
    auto item = PointerEventInterceptorList_.begin();
    for (auto it = PointerEventInterceptorList_.begin(); it != PointerEventInterceptorList_.end(); it++) {
        if (it->GetAuthority() > pHighestAuthority_) {
            pHighestAuthority_ = it->GetAuthority();
            pHighestId_ = it->GetId();
            item = it;
        }
    }
    if (pHighestId_ != 0) {
        MMI_LOGD("refound highest priority pointer event interceptor");
        MMIEventHdl.AddEventInterceptor(item->GetId(), item->GetName(), item->GetAuthority());
    }
    return RET_OK;
}

InputFilterManager::PointerEventInterceptor::PointerEventInterceptor(std::string name, Authority authority,
    std::function<void(MouseEvent)> handler) : name_(name), authority_(authority), handler_(handler)
{
    idManager_++;
    id_ = idManager_;
}

int32_t InputFilterManager::PointerEventInterceptor::GetId()
{
    return id_;
}

void InputFilterManager::PointerEventInterceptor::SetId(int32_t id)
{
    id_ = id;
}

std::string InputFilterManager::PointerEventInterceptor::GetName()
{
    return name_;
}

Authority InputFilterManager::PointerEventInterceptor::GetAuthority()
{
    return authority_;
}

std::function<void(MouseEvent)> InputFilterManager::PointerEventInterceptor::GetHandler()
{
    return handler_;
}

void InputFilterManager::OnPointerEventTrace(const MouseEvent& event)
{
    std::string pointerEvent = "client pointUuid = " + event.GetUuid();
    char *tmpPointer = (char*)pointerEvent.c_str();
    MMI_LOGT(" OnPointerEvent pointerUuid = %{public}s", tmpPointer);
    BYTRACE_NAME(BYTRACE_TAG_MULTIMODALINPUT, pointerEvent);
    int32_t eventPointer = 20;
    pointerEvent = "PointerEventFilterAsync";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, pointerEvent, eventPointer);
}

int32_t InputFilterManager::OnPointerEvent(MouseEvent event, int32_t id_)
{
    MMI_LOGD("client on point event call function handler ");
    OnPointerEventTrace(event);
    for (auto &item : PointerEventInterceptorList_)
    {
        if (id_ == item.GetId()) {
            item.GetHandler()(event);
            MMI_LOGD("client on point event call function handler success");
            break;
        }
    }
    return 0;
}

}
}

