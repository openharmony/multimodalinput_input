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

#ifndef TOUCH_TRANSFORM_POINT_PROCESSOR_H
#define TOUCH_TRANSFORM_POINT_PROCESSOR_H

#include <memory>
#include "pointer_event.h"
#include "input_windows_manager.h"
#include "window_switch.h"
namespace OHOS {
namespace MMI {
class TouchTransformPointProcessor {
public:
    TouchTransformPointProcessor();
    ~TouchTransformPointProcessor();
    std::shared_ptr<PointerEvent> onLibinputTouchEvent(libinput_event& event);
private:
    void onEventTouchDown(libinput_event& event);
    void onEventTouchMotion(libinput_event& event);
    void onEventTouchUp(libinput_event& event);
    std::shared_ptr<PointerEvent> pointerEvent_;
};
}
}

#endif
