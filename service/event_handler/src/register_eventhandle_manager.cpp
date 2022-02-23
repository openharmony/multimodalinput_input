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

#include "register_eventhandle_manager.h"
#include "proto.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "RegisterEventHandleManager" };
    }
RegisterEventHandleManager::RegisterEventHandleManager()
{
}

RegisterEventHandleManager::~RegisterEventHandleManager()
{
}

int32_t RegisterEventHandleManager::RegisterEvent(MmiMessageId messageId, int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHKR(messageId >= MmiMessageId::INVALID, PARAM_INPUT_INVALID, UNKNOWN_EVENT);
    switch (messageId) {
        case MmiMessageId::COMMON_EVENT_BEGIN:
            RegisterEventHandleIdMsage(MmiMessageId::COMMON_EVENT_BEGIN, MmiMessageId::COMMON_EVENT_END, fd);
            break;
        case MmiMessageId::KEY_EVENT_BEGIN:
            RegisterEventHandleIdMsage(MmiMessageId::KEY_EVENT_BEGIN, MmiMessageId::KEY_EVENT_END, fd);
            break;
        case MmiMessageId::MEDIA_EVENT_BEGIN:
            RegisterEventHandleIdMsage(MmiMessageId::MEDIA_EVENT_BEGIN, MmiMessageId::MEDIA_EVENT_END, fd);
            break;
        case MmiMessageId::SYSTEM_EVENT_BEGIN:
            RegisterEventHandleIdMsage(MmiMessageId::SYSTEM_EVENT_BEGIN, MmiMessageId::SYSTEM_EVENT_END, fd);
            break;
        case MmiMessageId::TELEPHONE_EVENT_BEGIN:
            RegisterEventHandleIdMsage(MmiMessageId::TELEPHONE_EVENT_BEGIN, MmiMessageId::TELEPHONE_EVENT_END, fd);
            break;
        case MmiMessageId::TOUCH_EVENT_BEGIN:
            RegisterEventHandleIdMsage(MmiMessageId::TOUCH_EVENT_BEGIN, MmiMessageId::TOUCH_EVENT_END, fd);
            break;
        default:
            MMI_LOGT("It's no this event handle");
            return UNKNOWN_EVENT;
    }
    MMI_LOGT("event:%{public}d,fd:%{public}d ", messageId, fd);
    return RET_OK;
}

int32_t RegisterEventHandleManager::UnregisterEventHandleManager(MmiMessageId messageId, int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHKR(messageId >= MmiMessageId::INVALID, PARAM_INPUT_INVALID, UNKNOWN_EVENT);
    switch (messageId) {
        case MmiMessageId::COMMON_EVENT_BEGIN:
            UnregisterEventHandleIdMsage(MmiMessageId::COMMON_EVENT_BEGIN, MmiMessageId::COMMON_EVENT_END, fd);
            break;
        case MmiMessageId::KEY_EVENT_BEGIN:
            UnregisterEventHandleIdMsage(MmiMessageId::KEY_EVENT_BEGIN, MmiMessageId::KEY_EVENT_END, fd);
            break;
        case MmiMessageId::MEDIA_EVENT_BEGIN:
            UnregisterEventHandleIdMsage(MmiMessageId::MEDIA_EVENT_BEGIN, MmiMessageId::MEDIA_EVENT_END, fd);
            break;
        case MmiMessageId::SYSTEM_EVENT_BEGIN:
            UnregisterEventHandleIdMsage(MmiMessageId::SYSTEM_EVENT_BEGIN, MmiMessageId::SYSTEM_EVENT_END, fd);
            break;
        case MmiMessageId::TELEPHONE_EVENT_BEGIN:
            UnregisterEventHandleIdMsage(MmiMessageId::TELEPHONE_EVENT_BEGIN, MmiMessageId::TELEPHONE_EVENT_END, fd);
            break;
        case MmiMessageId::TOUCH_EVENT_BEGIN:
            UnregisterEventHandleIdMsage(MmiMessageId::TOUCH_EVENT_BEGIN, MmiMessageId::TOUCH_EVENT_END, fd);
            break;
        default:
            MMI_LOGD("It's no this event handle! ");
            return UNKNOWN_EVENT;
    }
    return RET_OK;
}

void RegisterEventHandleManager::UnregisterEventHandleSocketFd(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    auto iter = mapRegisterManager_.begin();
    while (iter != mapRegisterManager_.end()) {
        if (iter->second == fd) {
            iter = mapRegisterManager_.erase(iter);
        } else {
            ++iter;
        }
    }
}

void RegisterEventHandleManager::FindSocketFds(const MmiMessageId messageId, std::vector<int32_t>& fds)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mapRegisterManager_.equal_range(messageId);
    if (it.first == std::end(mapRegisterManager_)) {
        MMI_LOGE("The message id was not found in the mapRegisterManager_, event:%{public}d", messageId);
        return;
    }
    for (auto iter = it.first; iter != it.second; ++iter) {
        fds.push_back(iter->second);
    }
}

void RegisterEventHandleManager::PrintfMap()
{
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &item : mapRegisterManager_) {
        std::cout << "event handle is "
            << static_cast<int32_t>(item.first)
            << ", fd is " << item.second << std::endl;
    }
}

void RegisterEventHandleManager::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    std::string strTmp;
    mprintf(fd, "RegsEvent: count=%d", mapRegisterManager_.size());
    for (auto it = mapRegisterManager_.begin(); it != mapRegisterManager_.end();
        it = mapRegisterManager_.upper_bound(it->first)) {
        strTmp.clear();
        auto evs = mapRegisterManager_.equal_range(it->first);
        strTmp = "type=";
        strTmp += std::to_string(static_cast<int32_t>(it->first)) + " fds:[";
        for (auto itr = evs.first; itr != evs.second; ++itr) {
            strTmp += std::to_string(itr->second) + ",";
        }
        strTmp.resize(strTmp.size()-1);
        strTmp += "]";
        mprintf(fd, "\t%s", strTmp.c_str());
    }
}

void RegisterEventHandleManager::Clear()
{
    if (mu_.try_lock()) {
        mu_.unlock();
    }
    mapRegisterManager_.clear();
}

void RegisterEventHandleManager::RegisterEventHandleIdMsage(const MmiMessageId idMsgBegin,
                                                            const MmiMessageId idMsgEnd,
                                                            const int32_t fd)
{
    const int32_t messageIdBeginTemp = static_cast<int32_t>(idMsgBegin);
    const int32_t messageIdEndTemp = static_cast<int32_t>(idMsgEnd);
    for (auto it = messageIdBeginTemp + 1; it < messageIdEndTemp; ++it) {
        auto tempId = static_cast<MmiMessageId>(it);
        mapRegisterManager_.insert(std::pair<MmiMessageId, int32_t>(tempId, fd));
    }
}

void RegisterEventHandleManager::UnregisterEventHandleIdMsage(const MmiMessageId idMsgBegin,
                                                              const MmiMessageId idMsgEnd,
                                                              const int32_t fd)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(static_cast<int32_t>(idMsgBegin) + 1);
    auto it = mapRegisterManager_.find(idMsg);
    while (it != mapRegisterManager_.end()) {
        if ((it->first < idMsgEnd) && (it->second == fd)) {
            it = mapRegisterManager_.erase(it);
        } else {
            ++it;
        }
    }
}
} // namespace MMI
} // namespace OHOS