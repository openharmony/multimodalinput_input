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

#include "uds_session.h"
#include <sstream>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UDSSession" };
}

UDSSession::UDSSession(const std::string& programName, const int moduleType, const int32_t fd,
    const int32_t uid, const int32_t pid)
    : programName_(programName),
      moduleType_(moduleType),
      fd_(fd),
      uid_(uid),
      pid_(pid)
{
    UpdateDescript();
}

UDSSession::~UDSSession()
{
}

bool UDSSession::SendMsg(const char *buf, size_t size) const
{
    CHKPF(buf);
    CHKF(size > 0 && size <= MAX_PACKET_BUF_SIZE, PARAM_INPUT_INVALID);
    CHKF(fd_ >= 0, PARAM_INPUT_INVALID);
    uint64_t ret = write(fd_, static_cast<void *>(const_cast<char *>(buf)), size);
    if (ret < 0) {
        const int errNoSaved = errno;
        MMI_LOGE("UDSSession::SendMsg write return %{public}" PRId64
                ", fd_:%{public}d, errNoSaved:%{public}d, strerror:%{public}s",
                ret, fd_, errNoSaved, strerror(errNoSaved));
        return false;
    }
    return true;
}

void UDSSession::Close()
{
    MMI_LOGT("enter fd_:%{public}d, bHasClosed_ = %d.", fd_, bHasClosed_);
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
    StreamBuffer buf;
    pkt.MakeData(buf);
    return SendMsg(buf.Data(), buf.Size());
}

void UDSSession::RecordEvent(int32_t id, uint64_t time)
{
    MMI_LOGI("begin");
    EventTime eventTime = {id, time};
    events_.push_back(eventTime);
    MMI_LOGI("end");
}

void UDSSession::ClearEventList(int32_t id)
{
    MMI_LOGI("begin");
    int32_t count = 0;
    for (auto &item : events_) {
        count++;
        if (item.id == id) {
            events_.erase(events_.begin(), events_.begin() + count);
            MMI_LOGI("Delete events.");
        }
    }
    MMI_LOGI("end");
}

uint64_t UDSSession::GetFirstEventTime()
{
    MMI_LOGI("begin");
    if (events_.empty()) {
        MMI_LOGT("events_ is empty");
        return 0;
    }
    MMI_LOGI("end");
    return events_[0].eventTime;
}

void UDSSession::ClearEventsVct()
{
    std::vector<EventTime>().swap(events_);
}
} // namespace MMI
} // namespace OHOS