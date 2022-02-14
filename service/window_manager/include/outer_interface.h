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

#ifndef OUTER_INTERFACE_H
#define OUTER_INTERFACE_H

#ifdef OHOS_WESTEN_MODEL
#include "key_event_value_transformation.h"

namespace OHOS {
namespace MMI {
enum MMI_SYSTEM_EVENT_ATTRIBUTE {
    MMI_SYSTEM_SERVICE = 1,
    MMI_SYSTEM_SERVICE_AND_APP = 2,
    MMI_CAMERA_APP = 3,
};

class OuterInterface {
public:
    OuterInterface();
    virtual ~OuterInterface();
    static bool SystemEventHandler(const KeyEventValueTransformations& trs, const enum KEY_STATE state,
        const int16_t systemEventAttr);
    static bool DistributedEventHandler(const KeyEventValueTransformations& trs, const enum KEY_STATE state,
        const int16_t systemEventAttr);
    static int32_t IsFocusChange(int32_t srcSurfaceId, int32_t desSurfaceId);
    static int32_t notifyFocusChange(int32_t abilityId, int32_t windowId);
    static int32_t GetSystemEventAttrByHosKeyValue(const int16_t keyValueOfHos);
};
};
}

#endif
#endif // OUTER_INTERFACE_H