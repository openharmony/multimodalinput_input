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
#ifndef OHOS_WINDOW_SWITCH_H
#define OHOS_WINDOW_SWITCH_H

#include <cstdio>
#include <iostream>
#include "libinput.h"
#include "input-event-codes.h"
#include "libmmi_util.h"

namespace OHOS {
namespace MMI {
class WindowSwitch {
public:
    WindowSwitch();
    ~WindowSwitch();
    void SetPointerByAbsMotion(const EventPointer& point);
    void SetPointerByMotion(const EventPointer& point);
    void SetPointerByButton(const EventPointer& point);
    void SetPointerByTouch(const EventTouch& touch);
    const EventPointer& GetEventPointer();
    const Pointer& GetPointer();
    void SetSize(size_t size);
    void SetSurfaceId(size_t windowId);
    size_t GetSize();
protected:
    void SetCommonPointer(const EventPointer& point);
    Pointer pointer_ = {};
    EventPointer eventPointer_ = {};
    size_t size_ = 3;
    size_t windowId_ = 0;
};
} // namespace mmis
} // namespace OHOS
#endif
