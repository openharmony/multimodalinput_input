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
#ifndef OHOS_STANDARD_EVENT_HANDLER_H
#define OHOS_STANDARD_EVENT_HANDLER_H
#include "libinput.h"
#include "input-event-codes.h"
#include "libmmi_util.h"

namespace OHOS {
namespace MMI {
class StandardEventHandler {
public:
    StandardEventHandler();
    virtual ~StandardEventHandler();
    void StandardTouchEvent(libinput_event *event, StandardTouchStruct& data);
    void PointerPressedStandard(libinput_event *event, StandardTouchStruct& data);
    void PointerPressedStandardEvent(struct libinput_event_pointer& szPoint, StandardTouchStruct& data);
    void PointerReleasedStandardEvent(struct libinput_event_pointer& szPoint, StandardTouchStruct& data);
    void PointerAbsoluteStandardEvent(libinput_event *event, StandardTouchStruct& data);
    void PointerMotionStandardEvent(libinput_event *event, StandardTouchStruct& data);
    void TipStandardEvent(libinput_event *event, StandardTouchStruct& data);
    void TipUpStandardEvent(struct libinput_event_tablet_tool& szPoint, StandardTouchStruct& data);
    void TipDownStandardEvent(struct libinput_event_tablet_tool& szPoint, StandardTouchStruct& data);
    void TipMotionStandardEvent(libinput_event *event, StandardTouchStruct& data);
private:
    libinput_button_state leftButtonState_ = {};
    uint32_t leftButton_ = 0;
};
}
}
#endif
