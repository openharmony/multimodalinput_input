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

#ifndef APP_REGISTER_H
#define APP_REGISTER_H
#include <set>
#include <vector>
#include "proto.h"
#include "uds_server.h"
#include "singleton.h"

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
    int32_t event;
    uint64_t inputTime;
    uint64_t westonTime;
    uint64_t serverTime;
};

class AppRegister : public DelayedSingleton<AppRegister> {
public:
    AppRegister();
    virtual ~AppRegister();

    bool Init(UDSServer& udsServer);

    const AppInfo& FindByWinId(int32_t windowId);

    const AppInfo& FindBySocketFd(int32_t fd);

    void RegisterAppInfoforServer(const AppInfo& appInfo);

    void UnregisterAppInfoBySocketFd(int32_t fd);

    void UnregisterConnectState(int32_t fd);

    void PrintfMap();
    void Dump(int32_t fd);
    void SurfacesDestroyed(const std::vector<int32_t> &desList);

    int32_t QueryMapSurfaceNum();

    bool IsMultimodeInputReady(MmiMessageId idMsg, const int32_t findFd, uint64_t inputTime, uint64_t westonTime = 0);

    WaitQueueEvent GetWaitQueueEvent(int32_t fd, int32_t idMsg);
    void DeleteEventFromWaitQueue(int32_t fd, int32_t idMsg);

    void RegisterConnectState(int32_t fd);

private:
    bool OnAnrLocked(int32_t fd) const;
    bool CheckFindFdError(const int32_t findFd);
    bool CheckConnectionIsDead(const int32_t findFd);
    bool CheckWaitQueueBlock(ssize_t currentTime, ssize_t timeOut, const int32_t findFd);
    void UnregisterBySocketFd(int32_t fd);

    std::map<int32_t, AppInfo>::iterator EraseAppInfo(const std::map<int32_t, AppInfo>::iterator &it);
    std::map<int32_t, AppInfo>::iterator UnregisterAppInfo(int32_t winId);

private:
    std::vector<int32_t> fds_;
    std::map<int32_t, AppInfo> mapSurface_ = {}; // key=windowId:value=AppInfo
    std::vector<WaitQueueEvent> waitQueue_ = {};
    std::map<int32_t, int8_t> mapConnectState_ = {};

    std::mutex mu_;
    UDSServer *udsServer_ = nullptr;
    const AppInfo appInfoError_ = {-1, -1, -1, "", ""};
};
} // namespace MMI
} // namespace OHOS
#define AppRegs OHOS::MMI::AppRegister::GetInstance()
#endif // APP_REGISTER_H