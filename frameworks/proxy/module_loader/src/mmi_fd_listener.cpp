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
#include "mmi_fd_listener.h"
#include <cinttypes>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "error_multimodal.h"
#include "mmi_log.h"
#include "stream_buffer.h"
#include "uds_socket.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MMIFdListener" };
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
    uint64_t tid = GetThisThreadIdOfLL();
    int32_t pid = GetPid();
    MMI_LOGD("enter. pid:%{public}d tid:%{public}" PRIu64, pid, tid);
    CHK(fd >= 0, C_INVALID_INPUT_PARAM);
    CHKPV(mmiClient_);

    StreamBuffer buf;
    bool isoverflow = false;
    char szBuf[MAX_PACKET_BUF_SIZE] = {};
    const int32_t maxCount = MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE + 1;
    CHK(maxCount > 0, VAL_NOT_EXP);
    for (int32_t i = 0; i < maxCount; i++) {
        auto size = recv(fd, szBuf, sizeof(szBuf), SOCKET_FLAGS);
        if (size < 0) {
            MMI_LOGE("recv return %{public}zu strerr:%{public}s", size, strerror(errno));
            break;
        } else if (size == 0) {
            MMI_LOGE("The service side disconnect with the client. size:0 strerr:%{public}s", strerror(errno));
            mmiClient_->OnDisconnect();
            break;
        } else if (size > 0) {
            if (!buf.Write(szBuf, size)) {
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

    // int32_t i = 10;
    // while (i-- >= 0) {
    //     std::this_thread::sleep_for(std::chrono::seconds(10));
    //     MMI_LOGW("OnReadable sleeping.... %{public}d pid:%{public}d tid:%{public}" PRIu64, i, pid, tid);
    // }
}

void MMIFdListener::OnShutdown(int32_t fd)
{
    uint64_t tid = GetThisThreadIdOfLL();
    int32_t pid = GetPid();
    MMI_LOGD("enter. pid:%{public}d tid:%{public}" PRIu64, pid, tid);
    CHK(fd >= 0, C_INVALID_INPUT_PARAM);
    CHKPV(mmiClient_);
    mmiClient_->OnDisconnect();
}

void MMIFdListener::OnException(int32_t fd)
{
    uint64_t tid = GetThisThreadIdOfLL();
    int32_t pid = GetPid();
    MMI_LOGD("enter. pid:%{public}d tid:%{public}" PRIu64, pid, tid);
    CHK(fd >= 0, C_INVALID_INPUT_PARAM);
    CHKPV(mmiClient_);
    mmiClient_->OnDisconnect();
}

} // namespace MMI
} // namespace OHOS
