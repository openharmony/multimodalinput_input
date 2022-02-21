/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef TOUCH_EVENT_HANDLER_H
#define TOUCH_EVENT_HANDLER_H

#include "standardized_event_handler.h"
#include "touch_event.h"

namespace OHOS {
namespace MMI {
class TouchEventHandler : public StandardizedEventHandler {
public:
    TouchEventHandler();
    virtual ~TouchEventHandler();
    virtual bool OnTouch(const TouchEvent& event) override;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_EVENT_HANDLER_H