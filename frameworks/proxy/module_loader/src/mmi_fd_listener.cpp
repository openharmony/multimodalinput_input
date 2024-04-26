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
    for (int32_t i = 0; i < MAX_RECV_LIMIT; i++) {
        ssize_t size = recv(fd, szBuf, MAX_PACKET_BUF_SIZE, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (size > 0) {
            mmiClient_->OnRecvMsg(szBuf, size);
        } else if (size < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_HILOGW("Continue for errno EAGAIN|EINTR|EWOULDBLOCK size:%{public}zu errno:%{public}d",
                    size, errno);
                continue;
            }
            MMI_HILOGE("Recv return %{public}zu errno:%{public}d", size, errno);
            break;
        } else {
            MMI_HILOGD("[Do nothing here]The service side disconnect with the client. size:0 count:%{public}d "
                "errno:%{public}d", i, errno);
            break;
        }
        if (size < MAX_PACKET_BUF_SIZE) {
            break;
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
