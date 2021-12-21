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

#ifndef OHOS_APP_REGISTER_H
#define OHOS_APP_REGISTER_H
#include <set>
#include <vector>
#include "proto.h"
#include "uds_server.h"
#include "c_singleton.h"

namespace OHOS {
namespace MMI {
struct AppInfo {
    int32_t abilityId;
    int32_t windowId;
    int32_t fd;
    std::string bundlerName;
    std::string appName;
};
struct WaitQueueEvent {
    int32_t fd;
    ssize_t currentTime;
    int32_t event;
};
struct ConnectStateByFd {
    int32_t connectState;
    int32_t inputBlocked;
};

class AppRegister : public CSingleton<AppRegister> {
public:
    AppRegister();
    virtual ~AppRegister();

    bool Init(UDSServer& udsServer);

    const AppInfo& FindByWinId(int32_t windowId);

    const AppInfo& FindBySocketFd(int32_t fd);

    void RegisterAppInfoforServer(const AppInfo& appInfo);

    void UnregisterAppInfoforServer(int32_t abilityId);

    void UnregisterAppInfoforServer(const AppInfo& appInfo);

    void UnregisterAppInfoBySocketFd(int32_t fd);

    void UnregisterConnectState(int32_t fd);

    void PrintfMap();
    void Dump(int32_t fd);

    int32_t QueryMapSurfaceNum();

    bool IsMultimodeInputReady(ssize_t currentTime, MmiMessageId idMsg, const int32_t findFd,
                               int32_t connectState = 0, int32_t bufferState = 0);

    void DeleteEventFromWaitQueue(ssize_t time, const int32_t fd);

    void RegisterConnectState(int32_t fd);

    void ConnectStateInputBlocked(const int32_t fd);

    bool ChkTestArg(int16_t anrErr)
    {
        return teseArgv_ == anrErr;
    }
    void SetTestArg(int16_t argv)
    {
        teseArgv_ = argv;
    }

#ifdef OHOS_AUTO_TEST_FRAME
    void AutoTestSetAutoTestFd(int32_t fd);
    int32_t AutoTestGetAutoTestFd();
    void AutoTestGetAllAppInfo(std::vector<AutoTestClientListPkt>& clientListPkt);
#endif  // OHOS_AUTO_TEST_FRAME

private:
    bool OnAnrLocked(int32_t fd) const;
    bool CheckFindFdError(const int32_t findFd);
    bool CheckConnectionIsDead(ssize_t currentTime, ssize_t timeOut, const int32_t findFd, int32_t connectState);
    bool CheckBufferIsFull(ssize_t currentTime, ssize_t timeOut, const int32_t findFd, int32_t bufferState);
    bool CheckWaitQueueBlock(ssize_t currentTime, ssize_t timeOut, const int32_t findFd);
    const AppInfo& FindAppInfoBySocketFd(int32_t fd);
    void UnregisterBySocketFd(int32_t fd);

private:
    int16_t teseArgv_ = 0;
    std::map<int32_t, AppInfo> mapSurface = {}; // key=windowId:value=AppInfo
    std::vector<WaitQueueEvent> waitQueue_ = {};
    std::map<int32_t, ConnectStateByFd> mapConnectState_ = {};
#ifdef OHOS_AUTO_TEST_FRAME
    int32_t autoTestFrameFd_ = 0;
#endif  // OHOS_AUTO_TEST_FRAME

    std::mutex mu_;
    UDSServer *udsServer_ = nullptr;
    const AppInfo AppInfoError_ = {-1, -1, -1, "", ""};
};
};
}
#define AppRegs OHOS::MMI::AppRegister::GetInstance()
#endif
