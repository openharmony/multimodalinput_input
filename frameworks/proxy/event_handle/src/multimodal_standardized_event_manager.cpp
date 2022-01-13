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
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "immi_token.h"
#include "input_event_data_transformation.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
            LOG_CORE, MMI_LOG_DOMAIN, "MultimodalStandardizedEventManager"
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
    for (StandEventMMaps::iterator it = range.first; it != range.second; ++it) {
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

int32_t MultimodalStandardizedEventManager::SubscribeKeyEvent(
    const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &subscribeInfo)
{
    OHOS::MMI::NetPacket pkt(MmiMessageId::SUBSCRIBE_KEY_EVENT);
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = subscribeInfo.GetKeyOption();
    uint32_t preKeySize = keyOption->GetPreKeySize();
    pkt << subscribeInfo.GetSubscribeId() << keyOption->GetFinalKey() << keyOption->IsFinalKeyDown()
    << keyOption->GetFinalKeyDownDuration() << preKeySize;
    std::vector<int32_t> preKeys = keyOption->GetPreKeys();
    for (auto preKeyIter = preKeys.begin(); preKeyIter != preKeys.end(); ++preKeyIter) {
        pkt << *preKeyIter;
    }
    if (SendMsg(pkt)) {
        return RET_OK;
    }
    return RET_ERR;
}

int32_t MultimodalStandardizedEventManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    OHOS::MMI::NetPacket pkt(MmiMessageId::UNSUBSCRIBE_KEY_EVENT);
    pkt << subscribeId;
    if (SendMsg(pkt)) {
        return RET_OK;
    }
    return RET_ERR;
}

int32_t OHOS::MMI::MultimodalStandardizedEventManager::OnKey(const OHOS::KeyEvent& event)
{
    MMI_LOGT("\nMultimodalStandardizedEventManagerkey::OnKey\n");
#ifdef DEBUG_CODE_TEST
    if (event.GetDeviceUdevTags() == HOS_VIRTUAL_KEYBOARD) {
        MMI_LOGT("Inject keyCode = %{public}d,action = %{public}d,revPid = %{public}d",
            event.GetKeyCode(), event.IsKeyDown(), GetPid());
    }
#endif
    auto range = mapEvents_.equal_range(MmiMessageId::KEY_EVENT_BEGIN);
    for (auto i = range.first; i != range.second; ++i) {
        if (i->second.windowId == event.GetWindowID() && i->second.eventCallBack->OnKey(event) == false) {
            MMI_LOGW("\n OnKey Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnTouch Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnShowMenu Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnSend Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnCopy Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnPaste Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnCut Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnUndo Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnRefresh Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnStartDrag Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnCancel Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnEnter Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnPrevious Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnNext Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnBack Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnPrint Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnPlay Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnPause Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnMediaControl Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnScreenShot Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnScreenSplit Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnStartScreenRecord Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnStopScreenRecord Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnGotoDesktop Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnRecent Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnShowNotification Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnLockScreen Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnSearch Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnClosePage Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnLaunchVoiceAssistant Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnMute Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnAnswer Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnRefuse Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnHangup Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnTelephoneControl Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnDeviceAdd Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
            MMI_LOGW("\n OnDeviceRemove Event consumption failed...errCode:%{public}d\n", EVENT_CONSUM_FAIL);
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
    OHOS::MMI::NetPacket ckv(MmiMessageId::ON_VIRTUAL_KEY);
    ckv << virtualevent;
    return SendMsg(ckv);
}

int32_t MultimodalStandardizedEventManager::InjectEvent(const OHOS::KeyEvent& keyEvent)
{
    VirtualKey virtualevent;
    if (keyEvent.GetKeyDownDuration() < 0) {
        MMI_LOGE("keyDownDuration is invalid");
        return false;
    }
    if (keyEvent.GetKeyCode() < 0) {
        MMI_LOGE("keyCode is invalid");
        return false;
    }
    virtualevent.isPressed = keyEvent.IsKeyDown();
    virtualevent.keyCode = keyEvent.GetKeyCode();
    virtualevent.keyDownDuration = keyEvent.GetKeyDownDuration();
    virtualevent.isIntercepted = keyEvent.IsIntercepted();
    OHOS::MMI::NetPacket ckv(MmiMessageId::INJECT_KEY_EVENT);
    ckv << virtualevent;
    return SendMsg(ckv);
}

int32_t MultimodalStandardizedEventManager::InjectEvent(const OHOS::MMI::KeyEvent& keyEvent)
{
    VirtualKey virtualevent;
    if (keyEvent.GetKeyCode() < 0) {
        MMI_LOGE("keyCode is invalid");
            return false;
    }
    virtualevent.isPressed = (keyEvent.GetKeyAction() == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    virtualevent.keyCode = keyEvent.GetKeyCode();
    virtualevent.keyDownDuration = 0;
    virtualevent.isIntercepted = false;
    OHOS::MMI::NetPacket ckv(MmiMessageId::INJECT_KEY_EVENT);
    ckv << virtualevent;
    return SendMsg(ckv);
}

int32_t MultimodalStandardizedEventManager::InjectEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> keyEventPtr)
{
    MMI_LOGD("InjectEvent begin");
    if (keyEventPtr == nullptr) {
        MMI_LOGE("KeyEventPtr is nullptr");
        return RET_ERR;
    }
    if (keyEventPtr->GetKeyCode() < 0) {
        MMI_LOGE("keyCode is invalid %{public}u", keyEventPtr->GetKeyCode());
        return RET_ERR;
    }
    OHOS::MMI::NetPacket ckv(MmiMessageId::NEW_INJECT_KEY_EVENT);
    int32_t errCode = OHOS::MMI::InputEventDataTransformation::KeyEventToNetPacket(keyEventPtr, ckv);
    if (errCode != RET_OK) {
        MMI_LOGE("Serialization is Failed! %{public}u", errCode);
        return RET_ERR;
    }
    return SendMsg(ckv);
}

int32_t MultimodalStandardizedEventManager::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Inject pointer event ...");
    CHKR(pointerEvent, NULL_POINTER, RET_ERR);
    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGD("\npointer event dispatcher of client:\neventType=%{public}d,actionTime=%{public}d,"
             "action=%{public}d,actionStartTime=%{public}d,"
             "flag=%{public}d,pointerAction=%{public}d,sourceType=%{public}d,"
             "VerticalAxisValue=%{public}.2f,HorizontalAxisValue=%{public}.2f,"
             "pointerCount=%{public}d",
             pointerEvent->GetEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetFlag(), pointerEvent->GetPointerAction(),
             pointerEvent->GetSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             static_cast<int32_t>(pointerIds.size()));

    for (int32_t pointerId : pointerIds) {
        OHOS::MMI::PointerEvent::PointerItem item;
        CHKR(pointerEvent->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        MMI_LOGD("\ndownTime=%{public}d,isPressed=%{public}s,"
                "globalX=%{public}d,globalY=%{public}d,localX=%{public}d,localY=%{public}d,"
                "width=%{public}d,height=%{public}d,pressure=%{public}d",
                 item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
                 item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
                 item.GetWidth(), item.GetHeight(), item.GetPressure());
    }

    std::vector<int32_t> pressedKeys = pointerEvent->GetPressedKeys();
    if (pressedKeys.empty()) {
        MMI_LOGI("Pressed keys is empty");
    } else {
        for (int32_t keyCode : pressedKeys) {
            MMI_LOGI("Pressed keyCode=%{public}d", keyCode);
        }
    }
    OHOS::MMI::NetPacket netPkt(MmiMessageId::INJECT_POINTER_EVENT);
    CHKR((RET_OK == InputEventDataTransformation::SerializePointerEvent(pointerEvent, netPkt)),
        STREAM_BUF_WRITE_FAIL, RET_ERR);
    MMI_LOGD("Pointer event packaged, send to server!");
    CHKR(SendMsg(netPkt), MSG_SEND_FAIL, RET_ERR);
    return RET_OK;
}

int32_t MultimodalStandardizedEventManager::GetDeviceIds(int32_t taskId)
{
    OHOS::MMI::NetPacket ckv(MmiMessageId::INPUT_DEVICE_ID_LIST);
    ckv << taskId;
    return SendMsg(ckv);
}

int32_t MultimodalStandardizedEventManager::GetDevice(int32_t taskId, int32_t deviceId)
{
    OHOS::MMI::NetPacket ckv(MmiMessageId::INPUT_DEVICE_INFO);
    ckv << taskId << deviceId;
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
