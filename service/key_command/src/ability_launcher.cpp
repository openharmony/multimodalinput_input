/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ability_launcher.h"

#include "ability_manager_client.h"
#include "bundle_name_parser.h"
#include "bytrace_adapter.h"
#include "dfx_hisysevent.h"
#include "input_event_handler.h"
#include "key_command_handler_util.h"
#include "key_shortcut_manager.h"
#include "nap_process.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AbilityLauncher"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t LIGHT_STAY_AWAY { 0 };
} // namespace

void AbilityLauncher::SetKeyCommandService(IKeyCommandService* service)
{
    keyCommandService_ = service;
}

void AbilityLauncher::LaunchAbility(const Ability &ability)
{
    CALL_DEBUG_ENTER;
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.uri);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }

    MMI_HILOGW("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    if (keyCommandService_ == nullptr) {
        MMI_HILOGE("[LaunchAbility] keyCommandService_ is null");
        return;
    }
    if (ability.abilityType == EXTENSION_ABILITY) {
        auto begin = std::chrono::high_resolution_clock::now();
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr);
        auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::ABILITY_MGR_START_EXT_ABILITY, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
    } else {
        auto begin = std::chrono::high_resolution_clock::now();
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::ABILITY_MGR_CLIENT_START_ABILITY, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
        auto sosBundleName = BUNDLE_NAME_PARSER.GetBundleName("SOS_BUNDLE_NAME");
        if (err == ERR_OK && ability.bundleName == sosBundleName) {
            keyCommandService_->HandleSosAbilityLaunched();
        }
    }
    keyCommandService_->ClearSpecialKeys();
    MMI_HILOGW("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
}

void AbilityLauncher::LaunchAbility(const Ability &ability, int64_t delay)
{
    CALL_DEBUG_ENTER;
    if (ability.bundleName.empty()) {
        MMI_HILOGW("BundleName is empty");
        return;
    }
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.uri);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }
    DfxHisysevent::CalcComboStartTimes(delay);
    DfxHisysevent::ReportComboStartTimes();
    MMI_HILOGW("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    auto begin = std::chrono::high_resolution_clock::now();
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::ABILITY_MGR_CLIENT_START_ABILITY, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    if (err != ERR_OK) {
        if (keyCommandService_ != nullptr) {
            keyCommandService_->ClearSpecialKeys();
        }
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        return;
    }
    int32_t state = NapProcess::GetInstance()->GetNapClientPid();
    if (state == REMOVE_OBSERVER) {
        MMI_HILOGW("nap client status:%{public}d", state);
        return;
    }
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = -1;
    napData.uid = -1;
    napData.bundleName = ability.bundleName;
    int32_t syncState = ACTIVE_EVENT;
    NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
    NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
    MMI_HILOGW("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    return;
}

void AbilityLauncher::LaunchRepeatKeyAbility(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_REPEAT_KEY, item.ability.bundleName);
    DfxHisysevent::ReportKeyEvent(item.ability.bundleName);
    std::string bundleName = item.ability.bundleName;
    std::string matchName = ".camera";
    if (keyCommandService_ == nullptr) {
        MMI_HILOGE("[LaunchRepeatKeyAbility] keyCommandService_ is null");
        return;
    }
    if (item.keyCode == KeyEvent::KEYCODE_VOLUME_DOWN && bundleName.find(matchName) != std::string::npos) {
        auto retValue = keyCommandService_->GetRetValue();
        MMI_HILOGI("retValue:%{public}d", retValue);
        if (retValue != LIGHT_STAY_AWAY) {
            LaunchAbility(item.ability);
            keyCommandService_->ResetLaunchAbilityCount();
            MMI_HILOGI("Launch yes");
        }
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
        keyCommandService_->UnregisterMistouchPrevention();
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    } else {
        LaunchAbility(item.ability);
    }
    BytraceAdapter::StopLaunchAbility();
    keyCommandService_->ClearRepeatKeyCountMap();
    auto subscriberHandler = InputHandler->GetSubscriberHandler();
    CHKPV(subscriberHandler);
    auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
    keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    subscriberHandler->HandleKeyEvent(keyEventCancel);
}
}  // namespace MMI
}  // namespace OHOS