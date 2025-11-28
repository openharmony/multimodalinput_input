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

#ifndef MMI_MOUSE_EVENT_NORMALIZE_MOCK_H
#define MMI_MOUSE_EVENT_NORMALIZE_MOCK_H

#include "gmock/gmock.h"
#include "libinput.h"
#include "nocopyable.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class IMouseEventNormalize {
public:
    IMouseEventNormalize() = default;
    virtual ~IMouseEventNormalize() = default;

    virtual bool CheckAndPackageAxisEvent(libinput_event*) = 0;
    virtual bool CheckFilterMouseEvent(struct libinput_event*) = 0;
    virtual std::shared_ptr<PointerEvent> GetPointerEvent() = 0;
    virtual std::shared_ptr<PointerEvent> GetPointerEvent(int32_t) = 0;
    virtual int32_t OnEvent(struct libinput_event*) = 0;
};

class MouseEventNormalize final : public IMouseEventNormalize {
public:
    static std::shared_ptr<MouseEventNormalize> GetInstance();
    static void ReleaseInstance();

    MouseEventNormalize() = default;
    ~MouseEventNormalize() override = default;
    DISALLOW_COPY_AND_MOVE(MouseEventNormalize);

    MOCK_METHOD(bool, CheckAndPackageAxisEvent, (struct libinput_event*));
    MOCK_METHOD(bool, CheckFilterMouseEvent, (struct libinput_event*));
    MOCK_METHOD(std::shared_ptr<PointerEvent>, GetPointerEvent, ());
    MOCK_METHOD(std::shared_ptr<PointerEvent>, GetPointerEvent, (int32_t));
    MOCK_METHOD(int32_t, OnEvent, (struct libinput_event*));

private:
    static std::shared_ptr<MouseEventNormalize> instance_;
};

#define MouseEventHdr MouseEventNormalize::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_MOUSE_EVENT_NORMALIZE_MOCK_H