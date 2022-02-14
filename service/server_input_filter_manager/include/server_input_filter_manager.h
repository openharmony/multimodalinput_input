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
#ifndef SERVER_INPUT_FILTER_MANAGER_H
#define SERVER_INPUT_FILTER_MANAGER_H
#include <vector>
#include <string>
#include "proto.h"
#include "uds_server.h"
#include "singleton.h"
#include "register_event.h"
#include "event_package.h"
#include "log.h"
#include "key_event.h"
namespace OHOS::MMI {
class ServerInputFilterManager : public DelayedSingleton<ServerInputFilterManager> {
public:
    class KeyEventFilter {
    public:
        KeyEventFilter(){}
        KeyEventFilter(int32_t id, std::string name, Authority authority);
        ~KeyEventFilter(){}
        int32_t GetId();
        std::string GetName();
        Authority GetAuthority();
        void SetAuthority(Authority authority);
        void SetName(std::string  name);
        void SetId(int32_t id);
    private:
        int32_t id_;
        std::string name_;
        Authority authority_;
    };
    bool OnKeyEvent(const EventKeyboard& key);
    int32_t AddKeyEventFilter(SessionPtr sess, std::string name, int32_t id, Authority authority);
    int32_t RemoveKeyEventFilter(SessionPtr sess, int32_t id);
    void DeleteFilterFromSess(SessionPtr sess);

public:
    class TouchEventFilter {
    public:
        TouchEventFilter(){}
        TouchEventFilter(int32_t id, std::string name, Authority authority);
        ~TouchEventFilter(){}
        int32_t GetId();
        std::string GetName();
        Authority GetAuthority();
        void SetAuthority(Authority authority);
        void SetName(std::string  name);
        void SetId(int32_t id);
    private:
        int32_t id_;
        std::string name_;
        Authority authority_;
    };
    bool OnTouchEvent(libinput_event *event, const EventTouch& touch, const uint64_t preHandlerTime);
    int32_t AddTouchEventFilter(SessionPtr sess, std::string name, int32_t id, Authority authority);
    int32_t RemoveTouchEventFilter(SessionPtr sess, int32_t id);
    int32_t RemoveTouchEventFilter(SessionPtr sess);

public:
    class PointerEventFilter {
    public:
        PointerEventFilter(){}
        PointerEventFilter(int32_t id_, std::string name_, Authority authority_);
        ~PointerEventFilter(){}
        int32_t GetId();
        std::string GetName();
        Authority GetAuthority();
        void SetAuthority(Authority authority);
        void SetName(std::string  name);
        void SetId(int32_t id);
    private:
        int32_t id_;
        std::string name_;
        Authority authority_;
    };
    bool OnPointerEvent(EventPointer event_pointer);
    int32_t RegisterEventInterceptorforServer(const SessionPtr& sess, int32_t id,
        std::string name, Authority authority);
    int32_t UnregisterEventInterceptorforServer(const SessionPtr& sess, int32_t id);
    void DeleteInterceptorFormSess(const SessionPtr& sess);

protected:
    void OnEventTouchGetPointEventType(const EventTouch& touch, const int32_t fingerCount,
        POINT_EVENT_TYPE& pointEventType);

protected:
    EventPackage eventPackage_;

private:
    std::map<SessionPtr, KeyEventFilter> keyEventFilterMap_;
    std::map<SessionPtr, TouchEventFilter> touchEventFilterMap_;
    std::map<SessionPtr, PointerEventFilter> pointerEventFilterMap_;
};
#define ServerKeyFilter OHOS::MMI::ServerInputFilterManager::GetInstance()
}

#endif // SERVER_INPUT_FILTER_MANAGER_H