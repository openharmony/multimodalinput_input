/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "mmi_fd_listener.h"

#include <cinttypes>

#include "config_multimodal.h"
#include "mmi_log.h"
#include "stream_buffer.h"
#include "uds_socket.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIFdListener" };
}

using namespace AppExecFwk;
MMIFdListener::MMIFdListener(MMIClientPtr client) : mmiClient_(client)
{
}

MMIFdListener::~MMIFdListener()
{
}

void MMIFdListener::OnReadable(int32_t fd)
{
    int32_t pid = GetPid();
    uint64_t tid = GetThisThreadId();
    MMI_LOGD("enter. fd:%{public}d pid:%{public}d tid:%{public}" PRIu64, fd, pid, tid);
    if (fd < 0) {
        MMI_LOGE("Invalid fd:%{public}d", fd);
        return;
    }
    CHKPV(mmiClient_);

    StreamBuffer buf;
    bool isoverflow = false;
    char szBuf[MAX_PACKET_BUF_SIZE] = {};
    constexpr int32_t maxCount = MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE + 1;
    if (maxCount <= 0) {
        MMI_LOGE("Invalid max count");
        return;
    }
    for (int32_t i = 0; i < maxCount; i++) {
        auto size = recv(fd, szBuf, MAX_PACKET_BUF_SIZE, SOCKET_FLAGS);
        if (size < 0) {
            int32_t eno = errno;
            if (eno == EAGAIN || eno == EINTR || eno == EWOULDBLOCK) {
                continue;
            }
            MMI_LOGE("recv return %{public}zu errno:%{public}d", size, eno);
            break;
        } else if (size == 0) {
            MMI_LOGE("The service side disconnect with the client. size:0 errno:%{public}d", errno);
            mmiClient_->OnDisconnect();
            break;
        } else {
            if (!buf.Write(szBuf, size)) {
                MMI_LOGE("write error or buffer overflow,count:%{}d size:%{}zu", i, size);
                isoverflow = true;
                break;
            }
        }
        if (size < MAX_PACKET_BUF_SIZE) {
            break;
        }
    }
    if (!isoverflow && buf.Size() > 0) {
        mmiClient_->OnRecvMsg(buf.Data(), buf.Size());
    }
}

void MMIFdListener::OnShutdown(int32_t fd)
{
    int32_t pid = GetPid();
    uint64_t tid = GetThisThreadId();
    MMI_LOGD("enter. fd:%{public}d pid:%{public}d tid:%{public}" PRIu64, fd, pid, tid);
    if (fd < 0) {
        MMI_LOGE("Invalid fd:%{public}d", fd);
    }
    CHKPV(mmiClient_);
    mmiClient_->OnDisconnect();
}

void MMIFdListener::OnException(int32_t fd)
{
    int32_t pid = GetPid();
    uint64_t tid = GetThisThreadId();
    MMI_LOGD("enter. fd:%{public}d pid:%{public}d tid:%{public}" PRIu64, fd, pid, tid);
    if (fd < 0) {
        MMI_LOGE("Invalid fd:%{public}d", fd);
    }
    CHKPV(mmiClient_);
    mmiClient_->OnDisconnect();
}
} // namespace MMI
} // namespace OHOS
