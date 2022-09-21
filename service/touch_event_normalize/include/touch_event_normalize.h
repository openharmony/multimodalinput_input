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

#ifndef TOUCH_EVENT_NORMALIZE_H
#define TOUCH_EVENT_NORMALIZE_H

#include <map>
#include <memory>

#include "proto.h"
#include "singleton.h"
#include "transform_processor.h"

namespace OHOS {
namespace MMI {
class TouchEventNormalize final {
    DECLARE_DELAYED_SINGLETON(TouchEventNormalize);
public:
    DISALLOW_COPY_AND_MOVE(TouchEventNormalize);
    std::shared_ptr<PointerEvent> OnLibInput(struct libinput_event *event, INPUT_DEVICE_TYPE deviceType);

private:
    std::shared_ptr<TransformProcessor> MakeTransformProcessor(
        int32_t deviceId, INPUT_DEVICE_TYPE deviceType) const;

private:
    std::map<int32_t, std::shared_ptr<TransformProcessor>> processors_;
};

#define TouchEventHdr ::OHOS::DelayedSingleton<TouchEventNormalize>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_EVENT_NORMALIZE_H