/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef TRANSFORM_PROCESSOR_H
#define TRANSFORM_PROCESSOR_H

#include <libinput.h>
#include <memory>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class TransformProcessor {
public:
    virtual std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) = 0;
    virtual std::shared_ptr<PointerEvent> GetPointerEvent() = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // TRANSFORM_PROCESSOR_H
