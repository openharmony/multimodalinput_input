/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTIMDOALINPUT_MOUSE_EVENT_HANDLER_H
#define OHOS_MULTIMDOALINPUT_MOUSE_EVENT_HANDLER_H

#include "libinput.h"
#include "pointer_event.h"
#include "input_windows_manager.h"

namespace OHOS {
namespace MMI {
class MouseEventHandler : public PointerEvent {
public:
    virtual ~MouseEventHandler();
    void SetMouseData(libinput_event& event, int32_t deviceId);
    static std::shared_ptr<MouseEventHandler> Create()
    {
        return std::shared_ptr<MouseEventHandler>(new MouseEventHandler(InputEvent::EVENT_TYPE_POINTER));
    }
protected:
    explicit MouseEventHandler(int32_t eventType);

    void SetMouseMotion(MouseInfo info, PointerEvent::PointerItem &pointerItem);
    void SetMouseButon(PointerEvent::PointerItem &pointerItem, struct libinput_event_pointer& pointEventData,
                       MouseInfo info);
    void SetMouseAxis(struct libinput_event_pointer& pointEventData, MouseInfo info,
                      PointerEvent::PointerItem &pointerItem);
    void CalcMovedCoordinate(struct libinput_event_pointer &pointEventData);
private:
    double coordinateX_ = 0;
    double coordinateY_ = 0;
};
}
} // namespace OHOS::MMI
#endif // OHOS_MULTIMDOALINPUT_POINTER_EVENT_H
