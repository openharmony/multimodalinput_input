/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "stylus_key_handler.h"

#include "ability_manager_client.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StylusKeyHandler"

namespace OHOS {
namespace MMI {
const std::string STYLUS_ABILITY_NAME = "HiNotePcMainAbility";
const std::string STYLUS_BUNDLE_NAME = "com.hmos.hinote";

StylusKeyHandler::StylusKeyHandler() {}
StylusKeyHandler::~StylusKeyHandler() {}

bool StylusKeyHandler::HandleStylusKey(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() != KeyEvent::KEYCODE_STYLUS_SCREEN) {
        stylusKey_.lastEventIsStylus = false;
        return false;
    }
    if (stylusKey_.isLaunchAbility) {
        stylusKey_.isLaunchAbility = false;
        return true;
    }
    stylusKey_.lastEventIsStylus = true;
    return false;
}

void StylusKeyHandler::IsLaunchAbility()
{
    if (stylusKey_.lastEventIsStylus) {
        stylusKey_.ability.abilityName = STYLUS_ABILITY_NAME;
        stylusKey_.ability.bundleName = STYLUS_BUNDLE_NAME;
        LaunchAbility(stylusKey_.ability);
        stylusKey_.lastEventIsStylus = false;
        stylusKey_.isLaunchAbility = true;
    }
}

void StylusKeyHandler::LaunchAbility(const Ability &ability)
{
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.type);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }

    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
    }
    MMI_HILOGD("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
}

void StylusKeyHandler::SetLastEventState(bool state)
{
    stylusKey_.lastEventIsStylus = state;
}

} // namespace AppExecFwk
} // namespace OHOS
