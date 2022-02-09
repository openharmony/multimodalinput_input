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
#ifndef MESSAGE_SEND_RECV_STAT_MGR_H
#define MESSAGE_SEND_RECV_STAT_MGR_H

#include "singleton.h"

namespace OHOS::MMI {
class MessageSendRecvStatMgr : public OHOS::Singleton<OHOS::MMI::MessageSendRecvStatMgr> {
public:
    MessageSendRecvStatMgr() = default;
    ~MessageSendRecvStatMgr() = default;
    void Increase();
    void Decrease();

    bool IsNoWaitMessage();
protected:
    size_t sendMessageCount_ = 0;
    size_t recvMessageCount_ = 0;
};
}

#endif // MESSAGE_SEND_RECV_STAT_MGR_H