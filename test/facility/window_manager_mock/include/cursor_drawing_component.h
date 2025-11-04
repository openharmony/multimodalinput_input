/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MMI_CURSOR_DRAWING_COMPONENT_MOCK_H
#define MMI_CURSOR_DRAWING_COMPONENT_MOCK_H

#include <gmock/gmock.h>
#include "delegate_interface.h"

namespace OHOS {
namespace MMI {
class ICursorDrawingComponent {
public:
    ICursorDrawingComponent() = default;
    virtual ~ICursorDrawingComponent() = default;

    virtual void Load() = 0;
    virtual void UnLoad() = 0;
    virtual bool Init() = 0;
    virtual void SetMouseDisplayState(bool state) = 0;
    virtual bool GetMouseDisplayState() = 0;
    virtual void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy) = 0;
    virtual void RegisterDisplayStatusReceiver() = 0;
    virtual void InitDefaultMouseIconPath() = 0;
    virtual void InitPointerCallback() = 0;
    virtual void InitScreenInfo() = 0;
    virtual void SubscribeScreenModeChange() = 0;
    virtual void InitPointerObserver() = 0;
};

class CursorDrawingComponent : public ICursorDrawingComponent {
public:
    CursorDrawingComponent() = default;
    virtual ~CursorDrawingComponent() override = default;

    MOCK_METHOD(void, Load, ());
    MOCK_METHOD(void, UnLoad, ());
    MOCK_METHOD(bool, Init, ());
    MOCK_METHOD(void, SetMouseDisplayState, (bool));
    MOCK_METHOD(bool, GetMouseDisplayState, ());
    MOCK_METHOD(void, SetDelegateProxy, (std::shared_ptr<DelegateInterface> proxy));
    MOCK_METHOD(void, RegisterDisplayStatusReceiver, ());
    MOCK_METHOD(void, InitDefaultMouseIconPath, ());
    MOCK_METHOD(void, InitPointerCallback, ());
    MOCK_METHOD(void, InitScreenInfo, ());
    MOCK_METHOD(void, SubscribeScreenModeChange, ());
    MOCK_METHOD(void, InitPointerObserver, ());

    static CursorDrawingComponent& GetInstance();
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_CURSOR_DRAWING_COMPONENT_MOCK_H