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

#include "system_event_handler.h"
#include <cstring>
#include "libmmi_util.h"

#ifdef OHOS_BUILD
#include "ability_manager.h"
#else
namespace OHOS::AAFwk {
class Want {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, OHOS::MMI::MMI_LOG_DOMAIN, "Want" };
public:
    static constexpr char const *FLAG_HOME_INTENT_FROM_SYSTEM = "AddEntityTest";

    Want() = default;
    ~Want() = default;
    Want& AddEntity(const std::string& entity)
    {
        MMI_LOGW("Want::AddEntity:%{public}s", entity.c_str());
        return *this;
    }
};
}

namespace OHOS::AppExecFwk {
class AbilityManager {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, OHOS::MMI::MMI_LOG_DOMAIN, "AbilityManager" };
public:
    AbilityManager() = default;
    virtual ~AbilityManager() = default;

    static AbilityManager& GetInstance()
    {
        static AbilityManager ttt;
        return ttt;
    }
    void StartAbility(const AAFwk::Want& want, int32_t requestCode = 0) const
    {
        MMI_LOGW("AbilityManager::StartAbility");
    }
};
}

#endif

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SystemEventHandler" };
    }
}
}

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
OHOS::MMI::SystemEventHandler::SystemEventHandler()
{
    mapFuns_ = {
        {MmiMessageId::ON_SCREEN_SHOT, std::bind(&SystemEventHandler::OnScreenShot, this)},
        {MmiMessageId::ON_SCREEN_SPLIT, std::bind(&SystemEventHandler::OnScreenSplit, this)},
        {MmiMessageId::ON_START_SCREEN_RECORD, std::bind(&SystemEventHandler::OnStopScreenRecord, this)},
        {MmiMessageId::ON_STOP_SCREEN_RECORD, std::bind(&SystemEventHandler::OnStartScreenRecord, this)},
        {MmiMessageId::ON_GOTO_DESKTOP, std::bind(&SystemEventHandler::OnGotoDesktop, this)},
        {MmiMessageId::ON_RECENT, std::bind(&SystemEventHandler::OnRecent, this)},
        {MmiMessageId::ON_SHOW_NOTIFICATION, std::bind(&SystemEventHandler::OnShowNotification, this)},
        {MmiMessageId::ON_LOCK_SCREEN, std::bind(&SystemEventHandler::OnLockScreen, this)},
        {MmiMessageId::ON_SEARCH, std::bind(&SystemEventHandler::OnSearch, this)},
        {MmiMessageId::ON_CLOSE_PAGE, std::bind(&SystemEventHandler::OnClosePage, this)},
        {MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT, std::bind(&SystemEventHandler::OnLaunchVoiceAssistant, this)},
        {MmiMessageId::ON_MUTE, std::bind(&SystemEventHandler::OnMute, this)},
        {MmiMessageId::ON_BACK, std::bind(&SystemEventHandler::OnBack, this)},
    };
}

OHOS::MMI::SystemEventHandler::~SystemEventHandler()
{
}

int32_t OHOS::MMI::SystemEventHandler::OnSystemEventHandler(MmiMessageId idMsg)
{
    if (idMsg == MmiMessageId::INVALID) {
        return PARAM_INPUT_INVALID;
    }
    auto fun = GetFun(idMsg);
    if (!fun) {
        MMI_LOGE("Non system event return");
        return UNKNOWN_MSG_ID; // non-system event return
    }
    (*fun)();
    return RET_OK;
}

void OHOS::MMI::SystemEventHandler::OnGotoDesktop()
{
    MMI_LOGI("SystemEventHandler::OnGotoDesktop");
    Want want;
    want.AddEntity(Want::FLAG_HOME_INTENT_FROM_SYSTEM);
    AbilityManager::GetInstance().StartAbility(want, 0);
}

void OHOS::MMI::SystemEventHandler::OnScreenShot()
{
    MMI_LOGI("SystemEventHandler::OnScreenShot");
}

void OHOS::MMI::SystemEventHandler::OnScreenSplit()
{
    MMI_LOGI("SystemEventHandler::OnScreenSplit");
}

void OHOS::MMI::SystemEventHandler::OnStopScreenRecord()
{
    MMI_LOGI("SystemEventHandler::OnStopScreenRecord");
}

void OHOS::MMI::SystemEventHandler::OnStartScreenRecord()
{
    MMI_LOGI("SystemEventHandler::OnStartScreenRecord");
}

void OHOS::MMI::SystemEventHandler::OnShowNotification()
{
    MMI_LOGI("SystemEventHandler::OnShowNotification");
}

void OHOS::MMI::SystemEventHandler::OnRecent()
{
    MMI_LOGI("SystemEventHandler::OnRecent");
}

void OHOS::MMI::SystemEventHandler::OnLockScreen()
{
    MMI_LOGI("SystemEventHandler::OnLockScreen");
}

void OHOS::MMI::SystemEventHandler::OnSearch()
{
    MMI_LOGI("SystemEventHandler::OnSearch");
}

void OHOS::MMI::SystemEventHandler::OnClosePage()
{
    MMI_LOGI("SystemEventHandler::OnClosePage");
}

void OHOS::MMI::SystemEventHandler::OnLaunchVoiceAssistant()
{
    MMI_LOGI("SystemEventHandler::OnLaunchVoiceAssistant");
}

void OHOS::MMI::SystemEventHandler::OnMute()
{
    MMI_LOGI("SystemEventHandler::OnMute");
}

void OHOS::MMI::SystemEventHandler::OnBack()
{
    MMI_LOGI("SystemEventHandler::OnBack");
}
