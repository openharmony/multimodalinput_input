/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mmi_fd_listener.h"

#include <cinttypes>

#include "config_multimodal.h"
#include "mmi_log.h"
#include "stream_buffer.h"
#include "uds_socket.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MMIFdListener"

namespace OHOS {
namespace MMI {
using namespace AppExecFwk;
MMIFdListener::MMIFdListener(MMIClientPtr client) : mmiClient_(client)
{
    CALL_DEBUG_ENTER;
}

void MMIFdListener::OnReadable(int32_t fd)
{
    if (fd < 0) {
        MMI_HILOGE("Invalid fd:%{public}d", fd);
        return;
    }
    CHKPV(mmiClient_);
    char szBuf[MAX_PACKET_BUF_SIZE] = {};
    ssize_t recvSize = 0;
    bool shouldTry = true;
    while (shouldTry) {
        ssize_t oneRecvSize = 0;
        while (oneRecvSize < MAX_PACKET_BUF_SIZE) {
            ssize_t size = recv(fd, szBuf + oneRecvSize, MAX_PACKET_BUF_SIZE - oneRecvSize,
                                MSG_DONTWAIT | MSG_NOSIGNAL);
            if (size > 0) {
                recvSize += size;
                oneRecvSize += size;
                continue;
            }

            // size 0 means it the fd may be closed.
            if (size == 0) {
                shouldTry = false;
                MMI_HILOGE("received %{public}zu, now received 0 from fd %{public}d, wait for next readable", recvSize,
                           fd);
                break;
            }

            // size < 0 means there is an error occurred, need to handle the error.
            int32_t recvError = errno;
            if (recvError == EAGAIN || recvError == EWOULDBLOCK) {
                shouldTry = false;
                break;
            } else if (recvError == EINTR) {
                MMI_HILOGW("received %{public}zu, fd %{public}d is interrupted by signal, continue to recv", recvSize,
                           fd);
                continue;
            } else {
                shouldTry = false;
                MMI_HILOGE("received %{public}zu, unexpected errno %{public}d on fd %{public}d, wait for next readable",
                           recvSize, recvError, fd);
                break;
            }
        }
        if (oneRecvSize > 0) {
            mmiClient_->OnRecvMsg(szBuf, oneRecvSize);
        }
    }
}

void MMIFdListener::OnShutdown(int32_t fd)
{
    CHK_PID_AND_TID();
    if (fd < 0) {
        MMI_HILOGE("Invalid fd:%{public}d", fd);
    }
    CHKPV(mmiClient_);
    mmiClient_->OnDisconnect();
}

void MMIFdListener::OnException(int32_t fd)
{
    CHK_PID_AND_TID();
    if (fd < 0) {
        MMI_HILOGE("Invalid fd:%{public}d", fd);
    }
    CHKPV(mmiClient_);
    mmiClient_->OnDisconnect();
}
} // namespace MMI
} // namespace OHOS
