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

#include "key_event_input_subscribe_filter.h"
#include "define_multimodal.h"
#include "input_event_data_transformation.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "KeyEventInputSubscribeFilter"};
}
const uint8_t KeyEventInputSubscribeFilter::maxPreKeyCount_ = 4;
int32_t KeyEventInputSubscribeFilter::SubscribeKeyEventForServer(
    SessionPtr sess, int32_t subscribeId, std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
{
    std::lock_guard<std::mutex> lock(mtx_);
    MMI_LOGD("server subscribe key event");
    if (subscribeId < 0) {
        MMI_LOGD("the [SubscribeId] is less than 0.");
        return RET_ERR;
    }
    if (keyOption == nullptr) {
        MMI_LOGD("the [KeyOption] is nullptr.");
        return RET_ERR;
    }
    if (keyOption->GetPreKeySize() > maxPreKeyCount_) {
        MMI_LOGD("the key option pre key size more than %{public}d", maxPreKeyCount_);
        return RET_ERR;
    }
    for (auto preKey : keyOption->GetPreKeys()) {
        MMI_LOGD("KeyOption->prekey=%{public}d", preKey);
    }
    MMI_LOGD("SubscribeId=%{public}d,KeyOption->finalKey=%{public}d,"
             "KeyOption->isFinalKeyDown=%{public}d,KeyOption->finalKeyDownDuriation=%{public}d",
             subscribeId, keyOption->GetFinalKey(), ((keyOption->IsFinalKeyDown() == true) ? 1 : 0),
             keyOption->GetFinalKeyDownDuration());
    auto mapIter = subscribeKeyEventInfoMap_.find(sess);
    if (mapIter != subscribeKeyEventInfoMap_.end()) {
        std::list<SubscribeKeyEventInfo> &subscribeKeyEventInfoList = mapIter->second;
        subscribeKeyEventInfoList.emplace_back(subscribeId, sess->GetFd(), keyOption);
    } else {
        std::list<SubscribeKeyEventInfo> subscribeKeyEventInfoList;
        subscribeKeyEventInfoList.emplace_back(subscribeId, sess->GetFd(), keyOption);
        subscribeKeyEventInfoMap_.insert(
            std::pair<SessionPtr, std::list<SubscribeKeyEventInfo>>(sess, subscribeKeyEventInfoList));
    }
    MMI_LOGD("server subscribe key event success. SubscribeId=%{public}d", subscribeId);
    return RET_OK;
}

int32_t KeyEventInputSubscribeFilter::UnSubscribeKeyEventForServer(SessionPtr sess, int32_t subscribeId)
{
    std::lock_guard<std::mutex> lock(mtx_);
    MMI_LOGD("server unsubscribe key event");
    if (subscribeId < 0) {
        MMI_LOGD("the SubscribeId is less than 0");
        return RET_ERR;
    }
    auto mapIter = subscribeKeyEventInfoMap_.find(sess);
    if (mapIter != subscribeKeyEventInfoMap_.end()) {
        std::list<SubscribeKeyEventInfo> &subscribeKeyEventInfoList = mapIter->second;
        auto listIter = subscribeKeyEventInfoList.begin();
        for (; listIter != subscribeKeyEventInfoList.end(); ++listIter) {
            if (listIter->GetSubscribeId() == subscribeId) {
                subscribeKeyEventInfoList.erase(listIter);
                MMI_LOGD("server unsubscribe key event success. SubscribeId=%{public}d", subscribeId);
            }
        }
        if (subscribeKeyEventInfoList.empty()) {
            MMI_LOGD("there is no subscribe key event of session. SubscribeId=%{public}d,Fd=%{public}d",
                     subscribeId, sess->GetFd());
            subscribeKeyEventInfoMap_.erase(mapIter);
        }
        return RET_OK;
    } else {
        MMI_LOGD("server unsubscribe key event,but cannot find subscribe key event info");
    }
    return RET_ERR;
}

bool KeyEventInputSubscribeFilter::FilterSubscribeKeyEvent(UDSServer& udsServer,
    std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    MMI_LOGD("server filter subscribe key event");
    if (subscribeKeyEventInfoMap_.empty()) {
        MMI_LOGD("there is no subscriber subscribe key event");
        return false;
    }
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    SubscribeKeyEventInfo subscribeKeyEventInfo = MatchSusbscribeKeyEvent(keyEvent, pressedKeys);
    if (subscribeKeyEventInfo.IsInValid()) {
        MMI_LOGD("there is no subscribe key match pressed keys");
        return false;
    }
    std::shared_ptr<OHOS::MMI::KeyOption> subscribeKeyOption = subscribeKeyEventInfo.GetKeyOption();
    int32_t keyAction = keyEvent->GetKeyAction();
    bool isFinalKeyDown = subscribeKeyOption->IsFinalKeyDown();
    if (keyAction == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN && isFinalKeyDown) {
        if (subscribeKeyOption->GetFinalKeyDownDuration() == 0) {
            MMI_LOGD("server filter subscribe key event down trigger");
            DispatchKeyEventSubscriber(udsServer, keyEvent, subscribeKeyEventInfo);
        } else {
            DelayDispatchKeyEventSubscriber(subscribeKeyOption->GetFinalKeyDownDuration(),
                udsServer, keyEvent, subscribeKeyEventInfo);
        }
        return true;
    } else if (keyAction == OHOS::MMI::KeyEvent::KEY_ACTION_UP && !isFinalKeyDown) {
        MMI_LOGD("server filter subscribe key event up trigger");
        DispatchKeyEventSubscriber(udsServer, keyEvent, subscribeKeyEventInfo);
        return true;
    }
    return false;
}

KeyEventInputSubscribeFilter::SubscribeKeyEventInfo KeyEventInputSubscribeFilter::MatchSusbscribeKeyEvent(
    std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent, const std::vector<int32_t>& pressedKeys)
{
    auto subscribeInfoMapIter = subscribeKeyEventInfoMap_.begin();
    for (; subscribeInfoMapIter != subscribeKeyEventInfoMap_.end(); ++subscribeInfoMapIter) {
        std::list<SubscribeKeyEventInfo> &subscribeKeyEventInfoList = subscribeInfoMapIter->second;  
        auto subscribeInfoListIter = subscribeKeyEventInfoList.begin();
        for (; subscribeInfoListIter != subscribeKeyEventInfoList.end(); ++subscribeInfoListIter) {
            std::shared_ptr<OHOS::MMI::KeyOption> subscribeKeyOption = subscribeInfoListIter->GetKeyOption();
            int32_t finalKey = subscribeKeyOption->GetFinalKey();
            MMI_LOGD("MatchSusbscribeKeyEvent: finalKey=%{public}d, keyEvent keyCode=%{public}d", finalKey, keyEvent->GetKeyCode());
            if (finalKey != keyEvent->GetKeyCode()) {
                continue;
            }
            std::vector<int32_t> preKeys = subscribeKeyOption->GetPreKeys();
            if (MatchPreKeysIsPressed(keyEvent->GetKeyAction(), preKeys, pressedKeys)) {
                return *subscribeInfoListIter;
            }
        }
    }
    return KeyEventInputSubscribeFilter::SubscribeKeyEventInfo::InValidSubscribeKeyEventInfo();
}

bool KeyEventInputSubscribeFilter::MatchPreKeysIsPressed(int32_t keyAction,
    const std::vector<int32_t>& preKeys, const std::vector<int32_t>& pressedKeys)
{
    MMI_LOGD("enter");
    int32_t preKeyCount = 0;
    for (auto keyIter = preKeys.begin(); keyIter != preKeys.end(); ++keyIter) {
        MMI_LOGD("subscribe key code:%{public}d", *keyIter);
        if (*keyIter < 0) {
            continue;
        }
        auto pressedKeyIter = std::find(pressedKeys.begin(), pressedKeys.end(), *keyIter);
        if (pressedKeyIter == pressedKeys.end()) {
            return false;
        }
        ++preKeyCount;
    }
    MMI_LOGD("preKeyCount=%{public}d,pressedKeySize=%{public}d", preKeyCount, static_cast<int32_t>(pressedKeys.size()));
    if (keyAction == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN && preKeyCount == (pressedKeys.size() - 1)) {
        return true;
    } else if (keyAction == OHOS::MMI::KeyEvent::KEY_ACTION_UP && preKeyCount == pressedKeys.size()) {
        return true;
    }
    return false;
}

void KeyEventInputSubscribeFilter::DispatchKeyEventSubscriber(
    UDSServer& udsServer, std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent,
    const SubscribeKeyEventInfo& subscribeInfo)
{
    MMI_LOGD("server disaptch subscribe key event to subscriber");
    OHOS::MMI::NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    int32_t fd = subscribeInfo.GetFd();
    pkt << fd << subscribeInfo.GetSubscribeId();
    if (!udsServer.SendMsg(fd, pkt)) {
        MMI_LOGD("server disaptch subscriber failed");
    }
}

void KeyEventInputSubscribeFilter::DelayDispatchKeyEventSubscriber(uint32_t timeOut,
    UDSServer& udsServer, std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent,
    const SubscribeKeyEventInfo& subscribeInfo)
{
    std::thread([this, timeOut, &udsServer, keyEvent, subscribeInfo]() {
        std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
        std::this_thread::sleep_for(std::chrono::milliseconds(timeOut));
        // other keys are pressed during the hold time
        if (pressedKeys != keyEvent->GetPressedKeys()) {
            MMI_LOGD("server filter subscribe key event down trigger duration: %{public}d,"
                     "but other keys are pressed during the hold time",
                     timeOut);
            return;
        }
        MMI_LOGD("server filter subscribe key event down trigger duration: %{public}d",
                 timeOut);
        DispatchKeyEventSubscriber(udsServer, keyEvent, subscribeInfo);
    }).detach();
}
}  // namespace MMI
}  // namespace OHOS