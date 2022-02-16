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
#ifndef MMI_SERVER_H
#define MMI_SERVER_H
#include "app_register.h"
#include "device_register.h"
#include "expansibility_operation.h"
#include "server_msg_handler.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "register_eventhandle_manager.h"

#ifndef OHOS_WESTEN_MODEL
    #include "s_input.h"
#endif
#ifdef OHOS_BUILD_HDF
    #include "hdf_event_manager.h"
#endif

#ifdef DEBUG_CODE_TEST
bool IsMmiServerWorking();
void SetMmiServerWorking();
int64_t GetMmiServerStartTime();
#endif

namespace OHOS {
namespace MMI {
class MMIServer : public UDSServer {
public:
    MMIServer();
    virtual ~MMIServer() override;
    int32_t Start();
    void OnTimer();
    void StopAll();

protected:
    int32_t SaConnectServiceRegister();
    int32_t SaConnectServiceStart();
    int32_t SaConnectServiceStop();
    virtual void OnConnected(SessionPtr s) override;
    virtual void OnDisconnected(SessionPtr s) override;

protected:
    ServerMsgHandler sMsgHandler_;
    ExpansibilityOperation expOper_;
#ifdef  OHOS_BUILD_AI
    SeniorInputFuncProcBase seniorInput_;
#endif // OHOS_BUILD_AI

#ifndef OHOS_WESTEN_MODEL
    SInput input_;
#endif
private:
    int32_t InitUds();
    int32_t InitExpSoLibrary();
    int32_t InitLibinput();
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_SERVER_H