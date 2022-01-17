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
#ifndef OHOS_SENIOR_INPUT_FUNC_PROC_BASE_H
#define OHOS_SENIOR_INPUT_FUNC_PROC_BASE_H
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class SeniorInputFuncProcBase : public RefBase {
public:
    SeniorInputFuncProcBase();
    virtual ~SeniorInputFuncProcBase();

    template<class T>
    static sptr<SeniorInputFuncProcBase> Create()
    {
        return sptr<SeniorInputFuncProcBase>(new T());
    }
    bool Init(UDSServer& sess);
    void SetSessionFd(int32_t fd);
    int32_t GetSessionFd();
    int32_t ReplyMessage(SessionPtr aiSessionPtr, int32_t status);

    bool DeviceInit(int32_t sessionId, sptr<SeniorInputFuncProcBase> ptr);
    bool DeviceEventDispatch(int32_t fd, RawInputEvent event);
    int32_t DeviceEventProcess(const RawInputEvent& event);
    void DeviceDisconnect(const int32_t sessionId);

    virtual int32_t DeviceEventDispatchProcess(const RawInputEvent &event);
    virtual int32_t GetDevType();

    int32_t sessionFd_ = 0;
    static UDSServer* udsServerPtr_;
    static std::map<int32_t, sptr<SeniorInputFuncProcBase>> deviceInfoMap_;
};
}
}
#endif