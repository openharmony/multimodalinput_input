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
#ifdef OHOS_WESTEN_MODEL
#include "outer_interface.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "OuterInterface" };
    }
const std::map<int16_t, int16_t> MAP_SYSTEM_EVENT_ATTR = {
    {HOS_KEY_MUTE, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_CALL, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MENU, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_PLAY, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_PAUSE, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_RECORD, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_VOLUME_UP, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_VOLUME_DOWN, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_VOLUME_MUTE, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_POWER, MMI_SYSTEM_SERVICE},
    {HOS_KEY_ENDCALL, MMI_SYSTEM_SERVICE},
    {HOS_KEY_HOME, MMI_SYSTEM_SERVICE},
    {HOS_KEY_BACK, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_CAMERA, MMI_CAMERA_APP},
    {HOS_KEY_BRIGHTNESS_UP, MMI_SYSTEM_SERVICE},
    {HOS_KEY_BRIGHTNESS_DOWN, MMI_SYSTEM_SERVICE},
    {HOS_KEY_FOCUS, MMI_CAMERA_APP},
    {HOS_KEY_SEARCH, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_PLAY_PAUSE, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_STOP, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_NEXT, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_PREVIOUS, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_REWIND, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_MEDIA_FAST_FORWARD, MMI_SYSTEM_SERVICE_AND_APP},
    {HOS_KEY_VOICE_ASSISTANT, MMI_SYSTEM_SERVICE},
};

OuterInterface::OuterInterface()
{
}

OuterInterface::~OuterInterface()
{
}

bool OuterInterface::SystemEventHandler(const KeyEventValueTransformations& trs,
                                        const enum KEY_STATE state, const int16_t systemEventAttr)
{
    switch (systemEventAttr) {
        case MMI_SYSTEM_SERVICE: {
            MMI_LOGT("Event dispatcher of server:Key:%{public}d,state:%{public}d,sourceType=300,"
                     "%{public}s is SystemKey, Dispatch to System Module",
                     trs.keyValueOfSys, state, trs.keyEvent.c_str());
            break;
        }
        case MMI_SYSTEM_SERVICE_AND_APP: {
            MMI_LOGT("Event dispatcher of server:Key:%{public}d,state:%{public}d,sourceType=300,"
                     "%{public}s is SystemKey, Dispatch to System Module. System Module return false",
                     trs.keyValueOfSys, state, trs.keyEvent.c_str());
            break;
        }
        case MMI_CAMERA_APP: {
            MMI_LOGT("Event dispatcher of server:Key:%{public}d,state:%{public}d,sourceType=300,"
                     "KEY_CAMERA is SystemKey, Dispatch to Camera Module",
                     trs.keyValueOfSys, state);
            break;
        }
        default: {
            break;
        }
    }
    return false;
}

bool OuterInterface::DistributedEventHandler(const KeyEventValueTransformations& trs,
                                             const enum KEY_STATE state, const int16_t systemEventAttr)
{
    switch (systemEventAttr) {
        case MMI_SYSTEM_SERVICE: {
            MMI_LOGT("Event dispatcher of server:Key:%{public}d,state:%{public}d,sourceType=300,"
                     "%{public}s is SystemKey, Dispatch to Distributed System",
                     trs.keyValueOfSys, state, trs.keyEvent.c_str());
            break;
        }
        case MMI_SYSTEM_SERVICE_AND_APP: {
            MMI_LOGT("Event dispatcher of server:Key:%{public}d,state:%{public}d,sourceType=300,"
                     "%{public}s is SystemKey, Dispatch to Distributed System. Distributed System return false",
                     trs.keyValueOfSys, state, trs.keyEvent.c_str());
            break;
        }
        case MMI_CAMERA_APP: {
            MMI_LOGT("Event dispatcher of server:Key:%{public}d,state:%{public}d,sourceType=300,"
                     "KEY_CAMERA is SystemKey, Dispatch to Distributed System",
                     trs.keyValueOfSys, state);
            break;
        }
        default: {
            break;
        }
        break;
    }
    return false;
}

/**
* @srcSurfaceId source windowid
* @desSurfaceId destinction windowid
* @return switched windowid;if not switched then return srcSurfaceId. if switched then return desSurfaceId.
*/
int OuterInterface::IsFocusChange(int32_t srcSurfaceId, int32_t desSurfaceId)
{
    return desSurfaceId;
}

/**
* @abilityId AbilityId
* @windowId focus windowid
* @return: if succeed then return 1 Or return -1.
*/
int OuterInterface::notifyFocusChange(int32_t abilityId, int32_t windowId)
{
    return RET_ERR;
}

int32_t OuterInterface::GetSystemEventAttrByKeyValue(const int16_t keyValueOfSys)
{
    auto it = MAP_SYSTEM_EVENT_ATTR.find(keyValueOfSys);
    if (it == MAP_SYSTEM_EVENT_ATTR.end()) {
        MMI_LOGE("No key found, keyValue:%{public}d", keyValueOfSys);
        return RET_ERR;
    }
    return it->second;
}
} // namespace MMI
} // namespace OHOS
#endif