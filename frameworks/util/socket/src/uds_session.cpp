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

#include "uds_session.h"
#include <sstream>
#include <fcntl.h>
#include <cinttypes>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UDSSession" };
} // namespace

UDSSession::UDSSession(const std::string& programName, const int32_t moduleType, const int32_t fd,
    const int32_t uid, const int32_t pid)
    : programName_(programName),
      moduleType_(moduleType),
      fd_(fd),
      uid_(uid),
      pid_(pid)
{
    UpdateDescript();
}

UDSSession::~UDSSession() {}

bool UDSSession::SendMsg(const char *buf, size_t size) const
{
    CHKPF(buf);
    if ((size == 0) || (size > MAX_PACKET_BUF_SIZE)) {
        MMI_LOGE("buf size:%{public}zu", size);
        return false;
    }
    if (fd_ < 0) {
        MMI_LOGE("fd_ is less than 0");
        return false;
    }

    int32_t idx = 0;
    int32_t retryCount = 0;
    const int32_t bufSize = static_cast<int32_t>(size);
    int32_t remSize = bufSize;
    while (remSize > 0 && retryCount < SEND_RETRY_LIMIT) {
        retryCount += 1;
        auto count = send(fd_, &buf[idx], remSize, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_LOGW("continue for errno EAGAIN|EINTR|EWOULDBLOCK, errno:%{public}d", errno);
                usleep(SEND_RETRY_SLEEP_TIME);
                continue;
            }
            MMI_LOGE("Send return failed,error:%{public}d fd:%{public}d", errno, fd_);
            return false;
        }
        idx += count;
        remSize -= count;
        if (remSize > 0) {
            usleep(SEND_RETRY_SLEEP_TIME);
        }
    }
    if (retryCount >= SEND_RETRY_LIMIT || remSize != 0) {
        MMI_LOGE("Send too many times:%{public}d/%{public}d,size:%{public}d/%{public}d fd:%{public}d",
            retryCount, SEND_RETRY_LIMIT, idx, bufSize, fd_);
        return false;
    }
    return true;
}

void UDSSession::Close()
{
    MMI_LOGD("enter fd_:%{public}d,bHasClosed_ = %d.", fd_, bHasClosed_);
    if (!bHasClosed_ && fd_ != -1) {
        close(fd_);
        bHasClosed_ = true;
        UpdateDescript();
    }
}

void UDSSession::UpdateDescript()
{
    std::ostringstream oss;
    oss << "fd = " << fd_
        << ", programName = " << programName_
        << ", moduleType = " << moduleType_
        << (bHasClosed_ ? ", closed" : ", opened")
#ifdef OHOS_BUILD_MMI_DEBUG
        << ", clientFd = " << clientFd_
#endif // OHOS_BUILD_MMI_DEBUG
        << std::endl;
    descript_ = oss.str().c_str();
}

bool UDSSession::SendMsg(NetPacket& pkt) const
{
    CHKF(!pkt.ChkRWError(), PACKET_WRITE_FAIL);
    StreamBuffer buf;
    pkt.MakeData(buf);
    return SendMsg(buf.Data(), buf.Size());
}

void UDSSession::AddEvent(int32_t id, int64_t time)
{
    MMI_LOGI("begin");
    EventTime eventTime = {id, time};
    events_.push_back(eventTime);
    MMI_LOGI("end");
}

void UDSSession::DelEvents(int32_t id)
{
    MMI_LOGI("begin");
    int32_t count = 0;
    for (auto &item : events_) {
        ++count;
        if (item.id == id) {
            events_.erase(events_.begin(), events_.begin() + count);
            MMI_LOGI("Delete events");
            break;
        }
    }
    auto currentTime = GetSysClockTime();
    if (events_.empty() || (currentTime < (events_.begin()->eventTime + INPUT_UI_TIMEOUT_TIME))) {
        isANRProcess_ = false;
    }
    MMI_LOGI("end");
}

int64_t UDSSession::GetFirstEventTime()
{
    MMI_LOGI("begin");
    if (events_.empty()) {
        MMI_LOGI("events_ is empty");
        return 0;
    }
    MMI_LOGI("end");
    return events_.begin()->eventTime;
}

bool UDSSession::EventsIsEmpty()
{
    if (events_.empty()) {
        MMI_LOGI("events_ is empty");
        return true;
    }
    return false;
}

void UDSSession::AddPermission(bool hasPermission)
{
    hasPermission_ = hasPermission;
}

bool UDSSession::HasPermission()
{
    return hasPermission_;
}
} // namespace MMI
} // namespace OHOS