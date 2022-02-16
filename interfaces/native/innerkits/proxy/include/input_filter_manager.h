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
#ifndef INPUT_FILTER_MANAGER_H
#define INPUT_FILTER_MANAGER_H
#include "singleton.h"
#include "proto.h"
#include <string>
#include <list>
#include <functional>
#include "keyboard_event.h"
#include "touch_event.h"
#include "multimodal_event_handler.h"
namespace OHOS {
namespace MMI {
class InputFilterManager : public Singleton<InputFilterManager> {
public:
    class KeyEventFilter {
    public:
        KeyEventFilter(){}
        KeyEventFilter(std::string name, Authority authority, std::function<void(KeyBoardEvent)> handler);
        void SetId(int32_t id);
        int32_t GetId();
        std::string GetName();
        Authority GetAuthority();
        std::function<void(KeyBoardEvent)> GetHandler();
        ~KeyEventFilter(){}
    private:
        int id_;
        std::string name_;
        Authority authority_;
        std::function<void(KeyBoardEvent)> handler_;
    };
    int32_t FilterKeyEvent(std::string name, Authority authority, std::function<void(KeyBoardEvent)> handler);
    int32_t UnFilterKeyEvent(int32_t id);
    int32_t OnKeyEvent(KeyBoardEvent event, int32_t id);

public:
    class TouchEventFilter {
    public:
        TouchEventFilter(){}
        TouchEventFilter(std::string name, Authority authority, std::function<void(TouchEvent)> handler);
        void SetId(int32_t id);
        int32_t GetId();
        std::string GetName();
        Authority GetAuthority();
        std::function<void(TouchEvent)> GetHandler();
        ~TouchEventFilter(){}
    private:
        int id_;
        std::string name_;
        Authority authority_;
        std::function<void(TouchEvent)> handler_;
    };
    int32_t FilterTouchEvent(std::string name, Authority authority, std::function<void(TouchEvent)> handler);
    int32_t UnFilterTouchEvent(int32_t id);
    int32_t OnTouchEvent(TouchEvent event, int32_t id);

public:
    class PointerEventInterceptor {
    public:
        PointerEventInterceptor(){}
        PointerEventInterceptor(std::string name_, Authority authority_, std::function<void(MouseEvent)> handler_);
        int32_t GetId();
        void SetId(int32_t id);
        std::string GetName();
        Authority GetAuthority();
        std::function<void(MouseEvent)> GetHandler();
        ~PointerEventInterceptor(){}

    private:
        int32_t id_;
        std::string name_;
        Authority authority_;
        std::function<void(MouseEvent)> handler_;
    };
    int32_t RegisterPointerEventInterceptor(std::string name_, Authority authority_,
                                            std::function<void(MouseEvent)> handler_);
    int32_t UnRegisterPointerEventInterceptor(int32_t id_);
    int32_t OnPointerEvent(MouseEvent event, int32_t id_);

private:
    int32_t GetHighAuthorityFilterId();
    TouchEventFilter GetTouchEventFilter(int32_t id);

private:
    std::list<KeyEventFilter> keyEventFilterList_;
    int32_t highestId_ {0};
    Authority highestAuthority_ {NO_AUTHORITY};
    static int32_t idManager_;

    std::list<TouchEventFilter> touchEventFilterList_;
    std::list<PointerEventInterceptor> PointerEventInterceptorList_;
    int32_t pHighestId_ {0};
    Authority pHighestAuthority_ {NO_AUTHORITY};
};
} // namespace MMI
} // namespace OHOS
#define InputFilterMgr OHOS::MMI::InputFilterManager::GetInstance()
#endif // INPUT_FILTER_MANAGER_H