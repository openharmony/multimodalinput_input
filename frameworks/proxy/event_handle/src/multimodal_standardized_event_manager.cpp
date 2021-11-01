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

#include "multimodal_standardized_event_manager.h"
#include "proto.h"
#include "error_multimodal.h"
#include "define_multimodal.h"
#include "net_packet.h"
#include "immi_token.h"

namespace OHOS {
namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN,
            "MultimodalStandardizedEventManager"
        };
    }

MultimodalStandardizedEventManager::MultimodalStandardizedEventManager() {}

MultimodalStandardizedEventManager::~MultimodalStandardizedEventManager() {}

void MultimodalStandardizedEventManager::SetClientHandle(MMIClientPtr client)
{
    MMI_LOGT("enter");
    client_ = client;
}

int32_t MultimodalStandardizedEventManager::RegisterStandardizedEventHandle(const sptr<IRemoteObject> token,
    int32_t windowId, StandEventPtr standardizedEventHandle)
{
    CHKR((token && standardizedEventHandle), PARAM_INPUT_INVALID, MMI_STANDARD_EVENT_INVALID_PARAMETER);
    auto messageId = standardizedEventHandle->GetType();
    CHKR(messageId > MmiMessageId::INVALID, VAL_NOT_EXP, MMI_STANDARD_EVENT_INVALID_PARAMETER);
    auto range = mapEvents_.equal_range(messageId);
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second.eventCallBack == standardizedEventHandle) {
            MMI_LOGE("Duplicate registration information, registration failed...errCode:%{public}d",
                     MMI_STANDARD_EVENT_EXIST);
            return OHOS::MMI_STANDARD_EVENT_EXIST;
        }
    }
    MMI_LOGT("Register app event:typeId=%{public}d;", messageId);
    std::string registerhandle;
    if (!MakeRegisterHandle(messageId, windowId, registerhandle)) {
        MMI_LOGE("Invalid registration parameter...errCode:%{public}d", MMI_STANDARD_EVENT_INVALID_PARAMETER);
        return OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER;
    }
    registerEvents_.insert(registerhandle);
    struct StandEventCallBack StandEventInfo = {};
    StandEventInfo.windowId = windowId;
    StandEventInfo.eventCallBack = standardizedEventHandle;
    mapEvents_.insert(std::make_pair(messageId, StandEventInfo));

    std::string bundlerName = "EmptyBundlerName";
    std::string appName = "EmptyAppName";
    auto abilityId = *reinterpret_cast<int32_t*>(token.GetRefPtr());
    /* 三方联调代码，token中带bundlerName和appName，本注释三方代码修改后打开
    auto mmiToken = static_cast<IMMIToken*>(token.GetRefPtr());
    if (mmiToken) {
        bundlerName = mmiToken->GetBundlerName();
        appName = mmiToken->GetName();
    }
    */

    OHOS::MMI::NetPacket ck(MmiMessageId::REGISTER_MSG_HANDLER);
    ck << messageId << abilityId << windowId << bundlerName << appName;
    SendMsg(ck);
    return OHOS::MMI_STANDARD_EVENT_SUCCESS;
}

int32_t MultimodalStandardizedEventManager::UnregisterStandardizedEventHandle(const sptr<IRemoteObject> token,
    int32_t windowId, StandEventPtr standardizedEventHandle)
{
    CHKR((token && standardizedEventHandle), PARAM_INPUT_INVALID, MMI_STANDARD_EVENT_INVALID_PARAMETER);
    auto typeId = standardizedEventHandle->GetType();
    CHKR(typeId > MmiMessageId::INVALID, VAL_NOT_EXP, MMI_STANDARD_EVENT_INVALID_PARAMETER);
    auto range = mapEvents_.equal_range(typeId);

    std::string registerhandle;
    if (!MakeRegisterHandle(typeId, windowId, registerhandle)) {
        MMI_LOGE("Invalid unregistration parameter...typeId:%{public}d,windowId:%{public}d,errCode:%{public}d",
                 typeId, windowId, MMI_STANDARD_EVENT_INVALID_PARAMETER);
        return MMI_STANDARD_EVENT_INVALID_PARAMETER;
    }
    registerEvents_.erase(registerhandle);
    bool isHandleExist = false;
    StandEventMMaps::iterator it = range.first;
    for (; it != range.second; ++it) {
        if (it->second.eventCallBack == standardizedEventHandle) {
            mapEvents_.erase(it);
            isHandleExist = true;
            break;
        }
    }
    if (!isHandleExist) {
        MMI_LOGE("Unregistration does not exist, Unregistration failed...typeId:%{public}d,windowId:%{public}d,"
                 "errCode:%{public}d", typeId, windowId, MMI_STANDARD_EVENT_NOT_EXIST);
        return MMI_STANDARD_EVENT_NOT_EXIST;
    }
    MMI_LOGD("Unregister app event:typeId=%{public}d;;", typeId);
    OHOS::MMI::NetPacket ck(MmiMessageId::UNREGISTER_MSG_HANDLER);
    ck << typeId;
    SendMsg(ck);
    return OHOS::MMI_STANDARD_EVENT_SUCCESS;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnKey(const KeyEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManagerkey::OnKey\n");
    auto range = mapEvents_.equal_range(MmiMessageId::KEY_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.windowId == event.GetWindowID() && i->second.eventCallBack->OnKey(event) == false) {
            MMI_LOGE("\n OnKey Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
            break;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnTouch(const TouchEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManagertouch::OnTouch\n");
    auto range = mapEvents_.equal_range(MmiMessageId::TOUCH_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.windowId == event.GetWindowID() && i->second.eventCallBack->OnTouch(event) == false) {
            MMI_LOGE("\n OnTouch Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
            break;
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnShowMenu(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnShowMenu\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnShowMenu(event) == false) {
            MMI_LOGE("\n OnShowMenu Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnSend(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnSend\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnSend(event) == false) {
            MMI_LOGE("\n OnSend Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnCopy(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnCopy\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnCopy(event) == false) {
            MMI_LOGE("\n OnCopy Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnPaste(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnPaste\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnPaste(event) == false) {
            MMI_LOGE("\n OnPaste Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnCut(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnCut\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnCut(event) == false) {
            MMI_LOGE("\n OnCut Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnUndo(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnUndo\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnUndo(event) == false) {
            MMI_LOGE("\n OnUndo Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnRefresh(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnRefresh\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnRefresh(event) == false) {
            MMI_LOGE("\n OnRefresh Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnStartDrag(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnStartDrag\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnStartDrag(event) == false) {
            MMI_LOGE("\n OnStartDrag Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnCancel(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnCancel\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnCancel(event) == false) {
            MMI_LOGE("\n OnCancel Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnEnter(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnEnter\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnEnter(event) == false) {
            MMI_LOGE("\n OnEnter Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnPrevious(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnPrevious\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnPrevious(event) == false) {
            MMI_LOGE("\n OnPrevious Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnNext(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnNext\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnNext(event) == false) {
            MMI_LOGE("\n OnNext Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnBack(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnBack\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnBack(event) == false) {
            MMI_LOGE("\n OnBack Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnPrint(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnPrint\n");
    auto range = mapEvents_.equal_range(MmiMessageId::COMMON_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnPrint(event) == false) {
            MMI_LOGE("\n OnPrint Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnPlay(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnPlay\n");
    auto range = mapEvents_.equal_range(MmiMessageId::MEDIA_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnPlay(event) == false) {
            MMI_LOGE("\n OnPlay Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnPause(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnPause\n");
    auto range = mapEvents_.equal_range(MmiMessageId::MEDIA_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnPause(event) == false) {
            MMI_LOGE("\n OnPause Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnMediaControl(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnMediaControl\n");
    auto range = mapEvents_.equal_range(MmiMessageId::MEDIA_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnMediaControl(event) == false) {
            MMI_LOGE("\n OnMediaControl Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnScreenShot(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnScreenShot\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnScreenShot(event) == false) {
            MMI_LOGE("\n OnScreenShot Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnScreenSplit(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnScreenSplit\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnScreenSplit(event) == false) {
            MMI_LOGE("\n OnScreenSplit Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnStartScreenRecord(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnStartScreenRecord\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnStartScreenRecord(event) == false) {
            MMI_LOGE("\n OnStartScreenRecord Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnStopScreenRecord(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnStopScreenRecord\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnStopScreenRecord(event) == false) {
            MMI_LOGE("\n OnStopScreenRecord Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnGotoDesktop(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnGotoDesktop\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnGotoDesktop(event) == false) {
            MMI_LOGE("\n OnGotoDesktop Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnRecent(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnRecent\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnRecent(event) == false) {
            MMI_LOGE("\n OnRecent Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnShowNotification(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnShowNotification\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnShowNotification(event) == false) {
            MMI_LOGE("\n OnShowNotification Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnLockScreen(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnLockScreen\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnLockScreen(event) == false) {
            MMI_LOGE("\n OnLockScreen Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnSearch(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnSearch\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnSearch(event) == false) {
            MMI_LOGE("\n OnSearch Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnClosePage(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnClosePage\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnClosePage(event) == false) {
            MMI_LOGE("\n OnClosePage Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnLaunchVoiceAssistant(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnLaunchVoiceAssistant\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnLaunchVoiceAssistant(event) == false) {
            MMI_LOGE("\n OnLaunchVoiceAssistant Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnMute(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnMute\n");
    auto range = mapEvents_.equal_range(MmiMessageId::SYSTEM_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnMute(event) == false) {
            MMI_LOGE("\n OnMute Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnAnswer(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnAnswer\n");
    auto range = mapEvents_.equal_range(MmiMessageId::TELEPHONE_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnAnswer(event) == false) {
            MMI_LOGE("\n OnAnswer Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnRefuse(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnRefuse\n");
    auto range = mapEvents_.equal_range(MmiMessageId::TELEPHONE_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnRefuse(event) == false) {
            MMI_LOGE("\n OnRefuse Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnHangup(const MultimodalEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnHangup\n");
    auto range = mapEvents_.equal_range(MmiMessageId::TELEPHONE_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnHangup(event) == false) {
            MMI_LOGE("\n OnHangup Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnTelephoneControl(const MultimodalEvent& event)
{
    MMI_LOGI("\nMultimodalStandardizedEventManager::OnTelephoneControl\n");
    auto range = mapEvents_.equal_range(MmiMessageId::TELEPHONE_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnTelephoneControl(event) == false) {
            MMI_LOGE("\n OnTelephoneControl Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t MultimodalStandardizedEventManager::OnDeviceAdd(const DeviceEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnDeviceAdd\n");
    auto range = mapEvents_.equal_range(MmiMessageId::DEVICE_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnDeviceAdd(event) == false) {
            MMI_LOGE("\n OnDeviceAdd Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

int32_t MultimodalStandardizedEventManager::OnDeviceRemove(const DeviceEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManager::OnDeviceRemove\n");
    auto range = mapEvents_.equal_range(MmiMessageId::DEVICE_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.eventCallBack->OnDeviceRemove(event) == false) {
            MMI_LOGE("\n OnDeviceRemove Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
        }
    }
    return RET_OK;
}

const StringSet *MultimodalStandardizedEventManager::GetRegisterEvent()
{
    return &registerEvents_;
}

void MultimodalStandardizedEventManager::ClearAll()
{
    mapEvents_.clear();
    registerEvents_.clear();
}

int32_t MultimodalStandardizedEventManager::InjectionVirtual(bool isPressed, int32_t keyCode,
                                                             int32_t keyDownDuration, int32_t maxKeyCode)
{
    VirtualKey virtualevent;
    virtualevent.isPressed = isPressed;
    virtualevent.keyCode = keyCode;
    virtualevent.keyDownDuration = keyDownDuration;
    virtualevent.maxKeyCode = maxKeyCode;
    OHOS::MMI::NetPacket ckv(MmiMessageId::ON_VIRTUAL_KEY);
    ckv << virtualevent;
    return SendMsg(ckv);
}

int32_t MultimodalStandardizedEventManager::InjectEvent(const KeyEvent& keyEvent)
{
    VirtualKey virtualevent;
    virtualevent.isPressed = keyEvent.IsKeyDown();
    virtualevent.keyCode = keyEvent.GetKeyCode();
    virtualevent.keyDownDuration = keyEvent.GetKeyDownDuration();
    virtualevent.maxKeyCode = keyEvent.GetMaxKeyCode();
    OHOS::MMI::NetPacket ckv(MmiMessageId::INJECT_KEY_EVENT);
    ckv << virtualevent;
    return SendMsg(ckv);
}

bool MultimodalStandardizedEventManager::SendMsg(NetPacket& pkt) const
{
    CHKF(client_, NULL_POINTER);
    return client_->SendMessage(pkt);
}

bool MultimodalStandardizedEventManager::MakeRegisterHandle(MmiMessageId typeId, int32_t windowId,
                                                            std::string& rhandle)
{
    rhandle = std::to_string(windowId) + ",";
    switch (typeId) {
        case MmiMessageId::COMMON_EVENT_BEGIN:
            rhandle += "commoneventhandle";
            break;
        case MmiMessageId::KEY_EVENT_BEGIN:
            rhandle += "keyeventhandle";
            break;
        case MmiMessageId::MEDIA_EVENT_BEGIN:
            rhandle += "mediaeventhandle";
            break;
        case MmiMessageId::SYSTEM_EVENT_BEGIN:
            rhandle += "systemeventhandle";
            break;
        case MmiMessageId::TELEPHONE_EVENT_BEGIN:
            rhandle += "telephoneeventhandle";
            break;
        case MmiMessageId::TOUCH_EVENT_BEGIN:
            rhandle += "toucheventhandle";
            break;
        case MmiMessageId::DEVICE_BEGIN:
            rhandle += "devicehandle";
            break;
        default:
            return false;
    }
    return true;
}
}
}
