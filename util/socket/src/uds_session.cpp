/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "uds_session.h"

#include <cinttypes>
#include <sstream>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "hisysevent.h"
#include "proto.h"
#include "uds_socket.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UDSSession"

namespace OHOS {
namespace MMI {
namespace {
const std::string FOUNDATION = "foundation";
} // namespace

UDSSession::UDSSession(const std::string &programName, const int32_t moduleType, const int32_t fd,
    const int32_t uid, const int32_t pid)
    : programName_(programName),
      moduleType_(moduleType),
      fd_(fd),
      uid_(uid),
      pid_(pid)
{
    UpdateDescript();
    events_[ANR_DISPATCH] = {};
    events_[ANR_MONITOR] = {};
    isAnrProcess_[ANR_DISPATCH] = false;
    isAnrProcess_[ANR_MONITOR] = false;
}

bool UDSSession::SendMsg(const char *buf, size_t size) const
{
    CHKPF(buf);
    if ((size == 0) || (size > MAX_PACKET_BUF_SIZE)) {
        MMI_HILOGE("buf size:%{public}zu", size);
        return false;
    }
    if (fd_ < 0) {
        MMI_HILOGE("The fd_ is less than 0");
        return false;
    }

    int32_t idx = 0;
    int32_t retryCount = 0;
    const int32_t bufSize = static_cast<int32_t>(size);
    int32_t remSize = bufSize;
    int32_t socketErrorNo = 0;
    while (remSize > 0 && retryCount < SEND_RETRY_LIMIT) {
        retryCount += 1;
        auto count = send(fd_, &buf[idx], remSize, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                socketErrorNo = errno;
                continue;
            }
            if (errno == ENOTSOCK) {
                MMI_HILOGE("Got ENOTSOCK error, turn the socket to invalid");
                invalidSocket_ = true;
            }
            MMI_HILOGE("Send return failed,error:%{public}d fd:%{public}d, pid:%{public}d", errno, fd_, pid_);
            return false;
        }
        idx += count;
        remSize -= count;
        if (remSize > 0) {
            MMI_HILOGW("Remsize:%{public}d", remSize);
            usleep(SEND_RETRY_SLEEP_TIME);
        }
    }
    if (socketErrorNo == EWOULDBLOCK) {
        ReportSocketBufferFull();
    }
    if (retryCount >= SEND_RETRY_LIMIT || remSize != 0) {
        MMI_HILOGE("Send too many times:%{public}d/%{public}d,size:%{public}d/%{public}d errno:%{public}d, "
                   "fd:%{public}d, pid:%{public}d", retryCount, SEND_RETRY_LIMIT, idx, bufSize, errno, fd_, pid_);
        return false;
    }
    return true;
}

void UDSSession::Close()
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Enter fd_:%{public}d", fd_);
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
        UpdateDescript();
    }
}

void UDSSession::UpdateDescript()
{
    std::ostringstream oss;
    oss << "fd = " << fd_
        << ", programName = " << programName_
        << ", moduleType = " << moduleType_
        << ((fd_ < 0) ? ", closed" : ", opened")
        << ", uid = " << uid_
        << ", pid = " << pid_
        << ", tokenType = " << tokenType_
        << std::endl;
    descript_ = oss.str().c_str();
}

bool UDSSession::SendMsg(NetPacket &pkt) const
{
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Read and write status is error");
        return false;
    }
    StreamBuffer buf;
    pkt.MakeData(buf);
    return SendMsg(buf.Data(), buf.Size());
}

void UDSSession::ReportSocketBufferFull() const
{
    int32_t ret = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT,
        "INPUT_EVENT_SOCKET_TIMEOUT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG",
        "remote client buffer full, cant send msg",
        "PROGRAM_NAME",
        programName_,
        "REMOTE_PID",
        pid_);
    if (ret != 0) {
        MMI_HILOGE("save input event socket timeout failed, ret:%{public}d", ret);
    }
}

void UDSSession::SaveANREvent(int32_t type, int32_t id, int64_t time, int32_t timerId)
{
    CALL_DEBUG_ENTER;
    EventTime eventTime = { id, time, timerId };
    auto iter = events_.find(type);
    if (iter != events_.end()) {
        iter->second.push_back(eventTime);
    }
}

std::vector<int32_t> UDSSession::GetTimerIds(int32_t type)
{
    auto iter = events_.find(type);
    if (iter == events_.end()) {
        MMI_HILOGE("Current events have no event type:%{public}d", type);
        return {};
    }
    std::vector<int32_t> timers;
    for (auto &item : iter->second) {
        timers.push_back(item.timerId);
        item.timerId = -1;
    }
    events_[iter->first] = iter->second;
    return timers;
}

std::list<int32_t> UDSSession::DelEvents(int32_t type, int32_t id)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Delete events, anr type:%{public}d, id:%{public}d, pid:%{public}d", type, id, pid_);
    auto iter = events_.find(type);
    if (iter == events_.end()) {
        MMI_HILOGE("Current events have no event type:%{public}d pid:%{public}d", type, pid_);
        return {};
    }
    auto &events = iter->second;
    int32_t canDelEventCount = 0;
    std::list<int32_t> timerIds;
    for (auto &item : events) {
        if (item.id > id) {
            break;
        }
        MMI_HILOGD("Delete event, anr type:%{public}d, id:%{public}d, timerId:%{public}d", type, item.id, item.timerId);
        timerIds.push_back(item.timerId);
        ++canDelEventCount;
    }
    if (canDelEventCount == 0) {
        MMI_HILOGD("Can not find event:%{public}d pid:%{public}d type:%{public}d", id, pid_, type);
        return timerIds;
    }
    events.erase(events.begin(), events.begin() + canDelEventCount);

    if (events.empty()) {
        isAnrProcess_[type] = false;
        return timerIds;
    }
    MMI_HILOGD("First event, anr type:%{public}d, id:%{public}d, timerId:%{public}d, pid: %{public}d",
        type, events.begin()->id, events.begin()->timerId, pid_);
    int64_t endTime = 0;
    if (!AddInt64(events.begin()->eventTime, INPUT_UI_TIMEOUT_TIME, endTime)) {
        MMI_HILOGE("The addition of endTime overflows");
        return timerIds;
    }
    auto currentTime = GetSysClockTime();
    if (currentTime < endTime) {
        isAnrProcess_[type] = false;
    }
    return timerIds;
}

int64_t UDSSession::GetEarliestEventTime(int32_t type) const
{
    CALL_DEBUG_ENTER;
    auto iter = events_.find(type);
    if (iter != events_.end()) {
        if (iter->second.empty()) {
            MMI_HILOGD("Current events is empty");
            return 0;
        }
        return iter->second.begin()->eventTime;
    }
    return 0;
}

bool UDSSession::IsEventQueueEmpty(int32_t type)
{
    CALL_DEBUG_ENTER;
    auto iter = events_.find(type);
    return (iter == events_.end() || (iter->second.empty()));
}
} // namespace MMI
} // namespace OHOS