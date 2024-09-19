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
#include "setting_datashare.h"
#include "system_ability_definition.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StylusKeyHandler"

namespace OHOS {
namespace MMI {
const std::string SHORTHAND_ABILITY_NAME { "HiNotePcMainAbility" };
const std::string SHORTHAND_BUNDLE_NAME { "com.hmos.hinote" };
const std::string MEMORANDUM_ABILITY_NAME { "MainAbility" };
const std::string MEMORANDUM_BUNDLE_NAME { "com.hmos.hinote.notepad" };
const std::string IS_SCREEN_OFF { "is_sceen_off" };
const std::string SHORTHAND_SWITCH { "shorthand_switch_state" };
const std::string SHORTHAND_TARGET { "shorthand_target" };

StylusKeyHandler::StylusKeyHandler() {}
StylusKeyHandler::~StylusKeyHandler() {}

bool StylusKeyHandler::HandleStylusKey(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (!isShortHandConfig_) {
        stylusKey_.statusConfig = SHORTHAND_SWITCH;
        CreateStatusConfigObserver(stylusKey_);
        shortHandTarget_.statusConfig = SHORTHAND_TARGET;
        CreateStatusConfigObserver(shortHandTarget_);
        isShortHandConfig_ = true;
    }
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

template <class T>
void StylusKeyHandler::CreateStatusConfigObserver(T& item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        bool statusValue = true;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        MMI_HILOGI("Config changed key:%{public}s, value:%{public}d", key.c_str(), statusValue);
        item.statusConfigValue = statusValue;
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.statusConfig, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
    }
    bool configVlaue = true;
    ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .GetBoolValue(item.statusConfig, configVlaue);
    if (ret != RET_OK) {
        MMI_HILOGE("Get value from setting date fail");
        return;
    }
    MMI_HILOGI("Get value success key:%{public}s, value:%{public}d", item.statusConfig.c_str(), configVlaue);
    item.statusConfigValue = configVlaue;
}

void StylusKeyHandler::IsLaunchAbility()
{
    if (stylusKey_.statusConfigValue && stylusKey_.lastEventIsStylus) {
        if (shortHandTarget_.statusConfigValue) {
            stylusKey_.ability.abilityName = SHORTHAND_ABILITY_NAME;
            stylusKey_.ability.bundleName = SHORTHAND_BUNDLE_NAME;
            stylusKey_.ability.params.emplace(IS_SCREEN_OFF, "true");
        } else {
            stylusKey_.ability.abilityName = MEMORANDUM_ABILITY_NAME;
            stylusKey_.ability.bundleName = MEMORANDUM_BUNDLE_NAME;
        }
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
