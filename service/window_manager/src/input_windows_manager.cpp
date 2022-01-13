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
#include "input_windows_manager.h"
#include <cstdio>
#include <cstdlib>
#include "app_register.h"
#include "event_dump.h"
#include "mmi_server.h"
#include "util.h"
#include "util_ex.h"
#include "pointer_drawing_manager.h"

namespace OHOS::MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputWindowsManager"};
}
}

using namespace OHOS::MMI;

static void SeatsInfoDebugPrint(const struct SeatInfo** seats)
{
    MMI_LOGT("Seats:");
    for (int i = 0; seats[i]; i++) {
        MMI_LOGT(" -Seat%{public}02d seatName:%{public}s, deviceFlags:%{public}d, focusWindowId:%{public}d", i + 1,
                 seats[i]->seatName, seats[i]->deviceFlags, seats[i]->focusWindowId);
        MMI_LOGT(".");
    }
}

OHOS::MMI::InputWindowsManager::InputWindowsManager()
{
}

OHOS::MMI::InputWindowsManager::~InputWindowsManager()
{
    Clear();
}
/*
 * FullName:  Init
 * Returns:   bool
 * Qualifier: init windows manager server
 */
bool OHOS::MMI::InputWindowsManager::Init(UDSServer& udsServer)
{
    // save server handle
    udsServer_ = &udsServer;
    SetSeatListener([]() {
        WinMgr->UpdateSeatsInfo();
    });
    SetScreenListener([]() {
        WinMgr->UpdateScreensInfo();
    });
    UpdateSeatsInfo();
    UpdateScreensInfo();
    return true;
}

void OHOS::MMI::InputWindowsManager::UpdateSeatsInfo()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (seatsInfo_ != nullptr) {
        FreeSeatsInfo(seatsInfo_);
    }
    seatsInfo_ = GetSeatsInfo();
    if (seatsInfo_ == nullptr) {
        MMI_LOGE("InputWindowsManager::UpdateSeatsInfo seatsInfo = nullptr");
        return;
    }
    if (seatsInfo_[0] && seatsInfo_[0]->focusWindowId > 0) {
        SetFocusId(seatsInfo_[0]->focusWindowId);
    }
    SeatsInfoDebugPrint(const_cast<const SeatInfo**>(seatsInfo_));
}

// LCOV_EXCL_STOP
void OHOS::MMI::InputWindowsManager::UpdateScreensInfo()
{
    std::lock_guard<std::mutex> lock(mu_);
    // free the last screen info
    if (screensInfo_ != nullptr) {
        FreeScreensInfo(screensInfo_);
    }
    screensInfo_ = GetScreensInfo();
    if (screensInfo_ == nullptr) {
        MMI_LOGE("InputWindowsManager::UpdateScreensInfo screensInfo_ = nullptr");
        return;
    }
    // save windows info
    SaveScreenInfoToMap(const_cast<const ScreenInfo**>(screensInfo_));
    PrintDebugInfo();
}

const std::vector<ScreenInfo>& OHOS::MMI::InputWindowsManager::GetScreenInfo() const
{
    return screenInfoVec_;
}

const CLMAP<int32_t, LayerInfo>& OHOS::MMI::InputWindowsManager::GetLayerInfo() const
{
    return layers_;
}

const CLMAP<int32_t, MMISurfaceInfo>& OHOS::MMI::InputWindowsManager::GetSurfaceInfo() const
{
    return surfaces_;
}

void OHOS::MMI::InputWindowsManager::InsertSurfaceInfo(const MMISurfaceInfo& tmpSurfaceInfo)
{
    std::lock_guard<std::mutex> lock(mu_);
    surfaces_.insert(std::pair<int32_t, MMISurfaceInfo>(tmpSurfaceInfo.surfaceId, tmpSurfaceInfo));
    MMI_LOGW("OnWindow InsertSurfaceInfo ChangeFocusSurfaceId old:%{public}d new:%{public}d", focusInfoID_,
             tmpSurfaceInfo.surfaceId);
    focusInfoID_ = tmpSurfaceInfo.surfaceId;
}

void OHOS::MMI::InputWindowsManager::PrintAllNormalSurface()
{
    std::lock_guard<std::mutex> lock(mu_);
    PrintDebugInfo();
}

void OHOS::MMI::InputWindowsManager::SetFocusSurfaceId(int32_t id)
{
    std::lock_guard<std::mutex> lock(mu_);
    SetFocusId(id);
}

void OHOS::MMI::InputWindowsManager::SetTouchFocusSurfaceId(int32_t id)
{
    std::lock_guard<std::mutex> lock(mu_);
    touchFocusId_ = id;
}

int32_t OHOS::MMI::InputWindowsManager::GetFocusSurfaceId() const
{
    return focusInfoID_;
}

int32_t OHOS::MMI::InputWindowsManager::GetTouchFocusSurfaceId() const
{
    return touchFocusId_;
}

void OHOS::MMI::InputWindowsManager::SetFocusId(int32_t id)
{
    focusInfoID_ = id;
}

void OHOS::MMI::InputWindowsManager::PrintDebugInfo()
{
    MMI_LOGT("***********seats info***********");
    if (seatsInfo_ == nullptr) {
        MMI_LOGT("seatsInfo_ is nullptr");
        return;
    }
    int32_t idx = 0;
    for (int i = 0; seatsInfo_[i]; i++) {
        idx = i + 1;
        MMI_LOGT(" -Seat%{public}02d: seatName: %{public}s, deviceFlags: %{public}d, focusWindowId: %{public}d", idx,
                 seatsInfo_[i]->seatName, seatsInfo_[i]->deviceFlags, seatsInfo_[i]->focusWindowId);
    }

    MMI_LOGT("***********screen info***********");
    for (auto& j : screenInfoVec_) {
        MMI_LOGT(" -screenId: %{public}d, connectorName: %{public}s, screenWidth: %{public}d, screenHeight: "
                 "%{public}d, screenNlayers: %{public}d", j.screenId, j.connectorName, j.width, j.height, j.nLayers);
    }

    MMI_LOGT("***********layer info***********");
    for (auto& k : layers_) {
        MMI_LOGT(" -layer_id: %{public}d, on_screen_id: %{public}d, nSurfaces: %{public}d src(xywh): [%{public}d, "
                 "%{public}d, %{public}d, %{public}d], dest(xywh): [%{public}d, %{public}d, %{public}d, %{public}d] "
                 "visibility: %{public}d, opacity: %{public}lf",
                 k.second.layerId, k.second.onScreenId, k.second.nSurfaces, k.second.srcX, k.second.srcY,
                 k.second.srcW, k.second.srcH, k.second.dstX, k.second.dstY, k.second.dstW, k.second.dstH,
                 k.second.visibility, k.second.opacity);
    }

    MMI_LOGT("***********window info***********");
    for (auto& m : surfaces_) {
        auto appFd = AppRegs->FindByWinId(m.second.surfaceId);
        MMI_LOGT(" -surface_id: %{public}d, on_screen_id: %{public}d, on_layer_id: %{public}d, src(xywh): [%{public}d,"
                 " %{public}d, %{public}d, %{public}d] desc(xywh): [%{public}d, %{public}d, %{public}d, %{public}d], "
                 "visibility: %{public}d, opacity: %{public}lf, appFd: %{public}d bundlerName: %{public}s appName: "
                 "%{public}s",
                 m.second.surfaceId, m.second.screenId, m.second.onLayerId, m.second.srcX, m.second.srcY,
                 m.second.srcW, m.second.srcH, m.second.dstX, m.second.dstY, m.second.dstW, m.second.dstH,
                 m.second.visibility, m.second.opacity, appFd.fd, appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}

size_t OHOS::MMI::InputWindowsManager::GetSurfaceIdList(IdsList& ids)
{
    const int32_t TEST_THREE_WINDOWS = 3;
    std::lock_guard<std::mutex> lock(mu_);
    for (auto i : surfaces_) {
        if (i.second.surfaceId != focusInfoID_ && TEST_THREE_WINDOWS != i.second.surfaceId) {
            ids.push_back(i.second.surfaceId);
        }
    }
    ids.push_back(focusInfoID_);
    return ids.size();
}

std::string OHOS::MMI::InputWindowsManager::GetSurfaceIdListString()
{
    IdsList ids;
    std::string str;
    auto idsSize = GetSurfaceIdList(ids);
    if (idsSize > 0) {
        str = IdsListToString(ids, ",");
    }
    return str;
}

void OHOS::MMI::InputWindowsManager::Clear()
{
    MMI_LOGD("InputWindowsManager destructor begin  ....");
    std::lock_guard<std::mutex> lock(mu_);
    if (seatsInfo_) {
        FreeSeatsInfo(seatsInfo_);
        seatsInfo_ = nullptr;
    }
    if (screensInfo_) {
        FreeScreensInfo(screensInfo_);
        screensInfo_ = nullptr;
    }
    focusInfoID_ = 0;
    screenInfoVec_.clear();
    layers_.clear();
    surfaces_.clear();
    surfacesList_.clear();
    MMI_LOGD("InputWindowsManager destructor end....");
}

void OHOS::MMI::InputWindowsManager::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    mprintf(fd, "screenInfos count=%zu", screenInfoVec_.size());
    for (auto& screen_info : screenInfoVec_) {
        mprintf(fd, "\tscreenId=%d connectorName=%s screenWidth= %d screenHeight=%d screenNlayers=%d",
                screen_info.screenId, screen_info.connectorName, screen_info.width, screen_info.height,
                screen_info.nLayers);
    }
    mprintf(fd, "layerInfos count=%zu", layers_.size());
    for (auto& layer_info : layers_) {
        mprintf(fd, "\tlayerId=%d dstX=%d dstY=%d dstW=%d dstH=%d srcX=%d"
                "srcY=%d srcW=%d srcH=%d opacity=%f visibility=%d onScreenId=%d nsurfaces=%d",
                layer_info.second.layerId, layer_info.second.dstX, layer_info.second.dstY,
                layer_info.second.dstW, layer_info.second.dstH, layer_info.second.srcX,
                layer_info.second.srcY, layer_info.second.srcW, layer_info.second.srcH,
                layer_info.second.opacity, layer_info.second.visibility,
                layer_info.second.onScreenId, layer_info.second.nSurfaces);
    }
    mprintf(fd, "surfaceInfos count=%zu", surfaces_.size());
    for (auto& mysurface_info : surfaces_) {
        auto appFd = AppRegs->FindByWinId(mysurface_info.second.surfaceId);
        mprintf(fd, "\tsurfaceId=%d dstX=%d dstY=%d dstW=%d dstH=%d srcX=%d"
                "srcY=%d srcW=%d srcH=%d opacity=%f visibility=%d onLayerId=%d appFd=%d bundlerName=%s appName=%s",
                mysurface_info.second.surfaceId, mysurface_info.second.dstX,
                mysurface_info.second.dstY, mysurface_info.second.dstW, mysurface_info.second.dstH,
                mysurface_info.second.srcX, mysurface_info.second.srcY, mysurface_info.second.srcW,
                mysurface_info.second.srcH, mysurface_info.second.opacity, mysurface_info.second.visibility,
                mysurface_info.second.onLayerId, appFd.fd, appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}

/*
 * FullName:  SaveScreenInfoToMap
 * Returns:   void
 * Qualifier: save screen info to MAP
 * Parameter: screen_info**
 */
void OHOS::MMI::InputWindowsManager::SaveScreenInfoToMap(const ScreenInfo** screenInfo)
{
    // check param
    CHK(udsServer_, NULL_POINTER);
    CHK(screenInfo, NULL_POINTER);
    CHK(*screenInfo, NULL_POINTER);

    // clear windows info
    screenInfoVec_.clear();
    layers_.clear();
    surfaces_.clear();

    // save windows info
    IdsList surfaceList;
    for (int32_t i = 0; screenInfo[i]; i++) {
        // save screen
        screenInfoVec_.push_back(*(screenInfo[i]));
        int32_t nlayers = screenInfo[i]->nLayers;
        LayerInfo** pstrLayerInfo = screenInfo[i]->layers;
        for (int32_t j = 0; j < nlayers; j++) {
            // save
            layers_.insert(std::pair<int32_t, LayerInfo>(pstrLayerInfo[j]->layerId, *(pstrLayerInfo[j])));
            // get nsurfaces
            int32_t nsurfaces = pstrLayerInfo[j]->nSurfaces;
            SurfaceInfo** pstrSurface = pstrLayerInfo[j]->surfaces;
            for (int32_t k = 0; k < nsurfaces; k++) {
                MMISurfaceInfo mySurfaceTmp = {};
                CHK(EOK == memcpy_s(&mySurfaceTmp, sizeof(mySurfaceTmp), pstrSurface[k], sizeof(SurfaceInfo)),
                    MEMCPY_SEC_FUN_FAIL);
                mySurfaceTmp.screenId = screenInfo[i]->screenId;
                surfaces_.insert(std::pair<int32_t, MMISurfaceInfo>(mySurfaceTmp.surfaceId, mySurfaceTmp));
                AddId(surfaceList, mySurfaceTmp.surfaceId);
            }
        }
    }
    // Destroyed windows
    if (!surfacesList_.empty()) {
        IdsList delList;
        auto delSize = CalculateDifference(surfacesList_, surfaceList, delList);
        if (delSize > 0) {
            // Processing destroyed windows
            AppRegs->SurfacesDestroyed(delList);
            auto winIdsStr = IdsListToString(delList, ",");
            MMI_LOGD("InputWindowsManager Some windows were destroyed... winIds:[%{public}s]", winIdsStr.c_str());
        }
    }
    surfacesList_ = surfaceList;
}

bool OHOS::MMI::InputWindowsManager::FindSurfaceByCoordinate(double x, double y, const SurfaceInfo& pstrSurface)
{
    if (x >= pstrSurface.srcX && x <= (pstrSurface.srcX + pstrSurface.srcW) &&
        y >= pstrSurface.srcY && y <= (pstrSurface.srcY + pstrSurface.srcH)) {
        return true;
    }
    return false;
}

bool OHOS::MMI::InputWindowsManager::GetTouchSurfaceId(const double x, const double y, std::vector<int32_t>& ids)
{
    std::lock_guard<std::mutex> lock(mu_);
    // check map empty
    if (!surfaces_.empty()) {
        int32_t newLayerId = -1;
        int32_t newSurfaceId = -1;
        for (auto it : surfaces_) {
            auto res = static_cast<MMISurfaceInfo*>(&it.second);
            CHKF(res, NULL_POINTER);
            // find window by coordinate
            if (FindSurfaceByCoordinate(x, y, *res)) {
                if (res->onLayerId > newLayerId) {
                    newLayerId = res->onLayerId;
                    newSurfaceId = res->surfaceId;
                }
            }
        }
        // push id
        if ((newSurfaceId != -1) && (newSurfaceId != focusInfoID_)) {
            ids.push_back(focusInfoID_);
            ids.push_back(newSurfaceId);
        } else if (newSurfaceId != -1) {
            ids.push_back(focusInfoID_);
        }
        return true;
    }
    return false;
}

const ScreenInfo* OHOS::MMI::InputWindowsManager::GetScreenInfo(int32_t screenId)
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& it : screenInfoVec_) {
        if (it.screenId == screenId) {
            return &it;
        }
    }
    return nullptr;
}

const LayerInfo* OHOS::MMI::InputWindowsManager::GetLayerInfo(int32_t layerId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = layers_.find(layerId);
    if (it == layers_.end()) {
        return nullptr;
    }
    return &it->second;
}

const MMISurfaceInfo* OHOS::MMI::InputWindowsManager::GetSurfaceInfo(int32_t sufaceId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = surfaces_.find(sufaceId);
    if (it == surfaces_.end()) {
        return nullptr;
    }
    return &it->second;
}

bool OHOS::MMI::InputWindowsManager::CheckFocusSurface(double x, double y, const MMISurfaceInfo& info) const
{
    if (x >= info.dstX && x <= (info.dstX + info.dstW) &&
        y >= info.dstY && y <= (info.dstY + info.dstH)) {
        return true;
    }
    return false;
}

const MMISurfaceInfo* OHOS::MMI::InputWindowsManager::GetTouchSurfaceInfo(double x, double y)
{
    std::lock_guard<std::mutex> lock(mu_);
    int32_t newLayerId = -1;
    const MMISurfaceInfo* surfacePtr = nullptr;
    for (auto& it : surfaces_) {
        // find window by coordinate
        if (CheckFocusSurface(x, y, it.second) && it.second.onLayerId >= newLayerId) {
            newLayerId = it.second.onLayerId;
            if (it.second.visibility == 1 && AppRegs->FindByWinId(it.second.surfaceId).fd > 0) {
                surfacePtr = &it.second;
            }
        }
    }
    return surfacePtr;
}

void OHOS::MMI::InputWindowsManager::TransfromToSurfaceCoordinate(double& x, double& y, const MMISurfaceInfo& info,
                                                                  bool debug)
{
    double oldX = x;
    double oldY = y;
    x = x - info.dstX;
    y = y - info.dstY;
    if (debug) {
        auto appFd = AppRegs->FindByWinId(info.surfaceId);
        MMI_LOGD("Transfrom touch coordinate... src:[%{public}lf, %{public}lf] focusSurface:%{public}d "
                 "surface:[%{public}d, %{public}d, %{public}d, %{public}d] dest:[%{public}lf, %{public}lf] "
                 "fd:%{public}d bundler:%{public}s appName:%{public}s",
                 oldX, oldY, info.surfaceId, info.dstX, info.dstY, info.dstW, info.dstH, x, y, appFd.fd,
                 appFd.bundlerName.c_str(), appFd.appName.c_str());
    }
}

/*********************************新框架接口添加****************************/
int32_t OHOS::MMI::InputWindowsManager::UpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
#ifdef OHOS_WESTEN_MODEL
    MMI_LOGD("enter");
    int32_t focId = GetFocusSurfaceId();
    CHKR(!(focId < 0), FOCUS_ID_OBTAIN_FAIL, FOCUS_ID_OBTAIN_FAIL);
    auto appInfo = AppRegs->FindByWinId(focId);
    if (appInfo.fd == RET_ERR) {
        return RET_ERR;
    }
    inputEvent->SetTargetWindowId(focId);
    if (!screenInfoVec_.empty()) {
        MMI_LOGD("screenInfoVec_->screenId = %{public}d", screenInfoVec_[0].screenId);
        inputEvent->SetTargetDisplayId(screenInfoVec_[0].screenId);
    } else {
        inputEvent->SetTargetDisplayId(0);
    }
    inputEvent->SetAgentWindowId(focId);
    MMI_LOGD("leave");
    return appInfo.fd;
#else
    MMI_LOGD("enter");
    int32_t pid = GetPidUpdateTarget(inputEvent);
    CHKR(pid > 0, PID_OBTAIN_FAIL, RET_ERR);
    int32_t fd = udsServer_->GetFdByPid(pid);
    CHKR(fd > 0, FD_OBTAIN_FAIL, RET_ERR);
    MMI_LOGD("leave");
    return fd;
#endif
}

int32_t OHOS::MMI::InputWindowsManager::GetPidUpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    MMI_LOGD("enter");
    if (logicalDisplays_.size() <= 0) {
        MMI_LOGE("logicalDisplays_ size is 0");
        return RET_ERR;
    }

    if (inputEvent->GetTargetDisplayId() == -1) {
        MMI_LOGD("target display id is -1");
        inputEvent->SetTargetDisplayId(logicalDisplays_[0].id);
        inputEvent->SetTargetWindowId(logicalDisplays_[0].focusWindowId);
        auto it = windowInfos_.find(logicalDisplays_[0].focusWindowId);
        if (it == windowInfos_.end()) {
            MMI_LOGE("can't find winfow info, focuswindowId:%{public}d", logicalDisplays_[0].focusWindowId);
            return RET_ERR;
        }
        inputEvent->SetAgentWindowId(it->second.agentWindowId);
        MMI_LOGD("pid:%{public}d", it->second.pid);
        return it->second.pid;
    }

    for (int32_t i = 0; i < logicalDisplays_.size(); i++) {
        if (logicalDisplays_[i].id != inputEvent->GetTargetDisplayId()) {
            continue;
        }
        MMI_LOGD("target display id is %{public}d", inputEvent->GetTargetDisplayId());
        inputEvent->SetTargetWindowId(logicalDisplays_[i].focusWindowId);
        auto it = windowInfos_.find(logicalDisplays_[i].focusWindowId);
        if (it == windowInfos_.end()) {
            MMI_LOGE("can't find winfow info, focuswindowId:%{public}d", logicalDisplays_[i].focusWindowId);
            return RET_ERR;
        }
        inputEvent->SetAgentWindowId(it->second.agentWindowId);
        MMI_LOGD("pid:%{public}d", it->second.pid);
        return it->second.pid;
    }

    MMI_LOGE("leave,cant't find logical display,target display id:%{public}d", inputEvent->GetTargetDisplayId());
    return RET_ERR;
}

void OHOS::MMI::InputWindowsManager::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    MMI_LOGD("InputWindowsManager::UpdateDisplayInfo enter");
    physicalDisplays_.clear();
    logicalDisplays_.clear();
    windowInfos_.clear();

    physicalDisplays_ = physicalDisplays;
    logicalDisplays_ = logicalDisplays;
    int32_t numLogicalDisplay = logicalDisplays.size();
    for (int32_t i = 0; i < numLogicalDisplay; i++) {
        int32_t numWindow = logicalDisplays[i].windowsInfo_.size();
        for (int32_t j = 0; j < numWindow; j++) {
            WindowInfo myWindow = logicalDisplays[i].windowsInfo_[j];
            windowInfos_.insert(std::pair<int32_t, WindowInfo>(myWindow.id, myWindow));
        }
    }
    if (logicalDisplays.size() > 0) {
        //DrawWgr->TellDisplayInfo(logicalDisplays[0].id, logicalDisplays[0].width, logicalDisplays_[0].height);
    }
    PrintDisplayDebugInfo();
    MMI_LOGD("InputWindowsManager::UpdateDisplayInfo leave");
}

void OHOS::MMI::InputWindowsManager::PrintDisplayDebugInfo()
{
    MMI_LOGD("physicalDisplays,num:%{public}d", static_cast<int32_t>(physicalDisplays_.size()));
    for (int32_t i = 0; i < static_cast<int32_t>(physicalDisplays_.size()); i++) {
        MMI_LOGD("physicalDisplays,id:%{public}d, leftDisplayId:%{public}d, upDisplayId:%{public}d, "
            "topLeftX:%{public}d, topLeftY:%{public}d, width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s, seatName:%{public}s, logicWidth:%{public}d, logicHeight:%{public}d, "
            "direction:%{public}d",
            physicalDisplays_[i].id, physicalDisplays_[i].leftDisplayId, physicalDisplays_[i].upDisplayId,
            physicalDisplays_[i].topLeftX, physicalDisplays_[i].topLeftY, physicalDisplays_[i].width,
            physicalDisplays_[i].height, physicalDisplays_[i].name.c_str(), physicalDisplays_[i].seatId.c_str(),
            physicalDisplays_[i].seatName.c_str(), physicalDisplays_[i].logicWidth, physicalDisplays_[i].logicHeight,
            physicalDisplays_[i].direction);
    }

    MMI_LOGD("logicalDisplays,num:%{public}d", static_cast<int32_t>(logicalDisplays_.size()));
    for (int32_t i = 0; i < static_cast<int32_t>(logicalDisplays_.size()); i++) {
        MMI_LOGD("logicalDisplays, id:%{public}d,topLeftX:%{public}d, topLeftY:%{public}d, "
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s, seatName:%{public}s,focusWindowId:%{public}d,window num:%{public}d",
            logicalDisplays_[i].id, logicalDisplays_[i].topLeftX, logicalDisplays_[i].topLeftY,
            logicalDisplays_[i].width, logicalDisplays_[i].height, logicalDisplays_[i].name.c_str(),
            logicalDisplays_[i].seatId.c_str(), logicalDisplays_[i].seatName.c_str(), logicalDisplays_[i].focusWindowId,
            static_cast<int32_t>(logicalDisplays_[i].windowsInfo_.size()));
    }

    MMI_LOGD("window info,num:%{public}d", static_cast<int32_t>(windowInfos_.size()));
    for (auto it = windowInfos_.begin(); it != windowInfos_.end(); ++it) {
        MMI_LOGD("windowId:%{public}d, id:%{public}d, pid:%{public}d,uid:%{public}d,topLeftX:%{public}d,"
            "topLeftY:%{public}d,width:%{public}d,height:%{public}d,displayId:%{public}d,agentWindowId:%{public}d,",
            it->first, it->second.id, it->second.pid, it->second.uid, it->second.topLeftX, it->second.topLeftY,
            it->second.width, it->second.height, it->second.displayId, it->second.agentWindowId);
    }
}

bool OHOS::MMI::InputWindowsManager::TpPoint2LogicDisplayPoint2(libinput_event_touch* touch,
    int32_t& logicalX, int32_t& logicalY, int32_t& logicalDisplayId)
{
    if (screensInfo_ != nullptr) {
        if ((*screensInfo_) != nullptr)
        logicalDisplayId = (*screensInfo_)->screenId;
        logicalX = static_cast<int32_t>(libinput_event_touch_get_x_transformed(touch, (*screensInfo_)->width));
        logicalY = static_cast<int32_t>(libinput_event_touch_get_y_transformed(touch, (*screensInfo_)->height));
        return true;
    }
    return false;
}

OHOS::MMI::PhysicalDisplayInfo* OHOS::MMI::InputWindowsManager::GetPhysicalDisplayById(int32_t id)
{
    for (auto &it : physicalDisplays_) {
        if (it.id == id) {
            return &it;
        }
    }
    return nullptr;
}

OHOS::MMI::PhysicalDisplayInfo* OHOS::MMI::InputWindowsManager::FindMatchedPhysicalDisplayInfo(const std::string seatId, const std::string seatName)
{
    for (auto &it : physicalDisplays_) {
        if (it.seatId == seatId && it.seatName == seatName) {
            return &it;
        }
    }
    return nullptr;
}

bool OHOS::MMI::InputWindowsManager::TansformTouchscreePointToLogicalDisplayPoint(libinput_event_touch* touch,
    int32_t targetDisplayId, int32_t& displayX, int32_t& displayY)
{

    auto info = FindMatchedPhysicalDisplayInfo("seat0","default0");
    if (info == nullptr) {
        MMI_LOGD("info is a nullptr, find display seat0:default0  failed by Physical");
        return false;
    }
    if (info->width <= 0) {
        return false;
    }

    if (info->height <= 0) {
        return false;
    }

    if (info->logicWidth <= 0 || info->logicHeight <= 0) {
        return false;
    }
    int32_t localPhysicalX = static_cast<int32_t>(libinput_event_touch_get_x_transformed(touch, info->width) + info->topLeftX);
    int32_t localPhysicalY = static_cast<int32_t>(libinput_event_touch_get_y_transformed(touch, info->height) + info->topLeftY);

    int32_t localLogcialX = (int32_t)(1L * info->logicWidth * localPhysicalX / info->width);
    int32_t localLogcialY = (int32_t)(1L * info->logicHeight * localPhysicalY / info->height);

    int32_t globalLogicalX = localLogcialX;
    int32_t globalLogicalY = localLogcialY;

    for (const PhysicalDisplayInfo* left =  GetPhysicalDisplayById(info->leftDisplayId); left != nullptr; left = GetPhysicalDisplayById(left->leftDisplayId)) {
        globalLogicalX += left->logicWidth;
    }

    for (const PhysicalDisplayInfo* upper =  GetPhysicalDisplayById(info->upDisplayId); upper != nullptr; upper = GetPhysicalDisplayById(upper->upDisplayId)) {
        globalLogicalY += upper->logicHeight;
    }

    for (auto& display : logicalDisplays_) {
        if (targetDisplayId == display.id ) {
            displayX = globalLogicalX - display.topLeftX;
            displayY = globalLogicalY - display.topLeftY;
        }
        return true;
    }

    return false;
}

bool OHOS::MMI::InputWindowsManager::TpPointLogicDisplayPoint(libinput_event_touch* touch,
    int32_t& logicalX, int32_t& logicalY, int32_t& logicalDisplayId)
{

    auto info = FindMatchedPhysicalDisplayInfo("seat0","default0");
    if (info == nullptr) {
        MMI_LOGD("info is a nullptr, find display seat0:default0  failed by Physical");
        return false;
    }
    if (info->width <= 0) {
        return false;
    }

    if (info->height <= 0) {
        return false;
    }

    if (info->logicWidth <= 0 || info->logicHeight <= 0) {
        return false;
    }
    int32_t localPhysicalX = static_cast<int32_t>(libinput_event_touch_get_x_transformed(touch, info->width) + info->topLeftX);
    int32_t localPhysicalY = static_cast<int32_t>(libinput_event_touch_get_y_transformed(touch, info->height) + info->topLeftY);

    int32_t localLogcialX = (int32_t)(1L * info->logicWidth * localPhysicalX / info->width);
    int32_t localLogcialY = (int32_t)(1L * info->logicHeight * localPhysicalY / info->height);

    int32_t globalLogicalX = localLogcialX;
    int32_t globalLogicalY = localLogcialY;

    for (const PhysicalDisplayInfo* left =  GetPhysicalDisplayById(info->leftDisplayId); left != nullptr; left = GetPhysicalDisplayById(left->leftDisplayId)) {
        globalLogicalX += left->logicWidth;
    }

    for (const PhysicalDisplayInfo* upper =  GetPhysicalDisplayById(info->upDisplayId); upper != nullptr; upper = GetPhysicalDisplayById(upper->upDisplayId)) {
        globalLogicalY += upper->logicHeight;
    }

    for (auto& display : logicalDisplays_) {
        if (globalLogicalX < display.topLeftX || globalLogicalX > display.topLeftX + display.width) {
            continue;
        }

        if (globalLogicalY < display.topLeftY || globalLogicalY > display.topLeftY + display.height) {
            continue;
        }

        logicalDisplayId = display.id;
        logicalX = globalLogicalX - display.topLeftX;
        logicalY = globalLogicalY - display.topLeftY;
        return true;
    }

    return false;
}
const std::vector<struct LogicalDisplayInfo>& OHOS::MMI::InputWindowsManager::GetLogicalDisplayInfo() const
{
    return logicalDisplays_;
}

const CLMAP<int32_t, struct WindowInfo>& OHOS::MMI::InputWindowsManager::GetWindowInfo() const
{
    return windowInfos_;
}

bool OHOS::MMI::InputWindowsManager::isTouchWindow(int32_t x, int32_t y, const WindowInfo &info) const
{
    return x >= info.topLeftX && x <= (info.topLeftX + info.width) && y >= info.topLeftY &&
        y <= (info.topLeftY + info.height);
}

void OHOS::MMI::InputWindowsManager::ReviseGlobalCoordinate(int32_t& globalX, int32_t& globalY, int32_t width, int32_t height)
{
    if (globalX <= 0) {
        globalX = 0;
    }
    if (globalX >= width) {
        globalX = width;
    }
    if (globalY <= 0) {
        globalY = 0;
    }
    if (globalY >= height) {
        globalY = height;
    }
}

bool OHOS::MMI::InputWindowsManager::CheckDisplayIdIfExist(int32_t& displayId)
{
    if (logicalDisplays_.empty()) {
        MMI_LOGE("logicalDisplays_is empty address is %{public}p", &logicalDisplays_);
        return false;
    }
    if (displayId <= 0) {
        displayId = logicalDisplays_[0].id;
        return true;
    }
    for (auto it : logicalDisplays_) {
        if (it.id == displayId) {
            return true;
        }
    }
    return false;
}

bool OHOS::MMI::InputWindowsManager::GetLogicalDisplayById(int32_t displayId, LogicalDisplayInfo& logicalDisplayInfo)
{
    for (auto it : logicalDisplays_) {
        if (it.id == displayId) {
            logicalDisplayInfo = it;
            return true;
        }
    }
    return false;
}

void OHOS::MMI::InputWindowsManager::AdjustCoordinate(double &coordinateX, double &coordinateY)
{
    if (coordinateX < 0) {
        coordinateX = 0;
    }

    if (coordinateY < 0) {
        coordinateY = 0;
    }

    if (logicalDisplays_.size() == 0) {
        return;
    }

    if (coordinateX > logicalDisplays_[0].width) {
        coordinateX = logicalDisplays_[0].width;
    }
    if (coordinateY > logicalDisplays_[0].height) {
        coordinateY = logicalDisplays_[0].height;
    }
}

void OHOS::MMI::InputWindowsManager::FixCursorPosition(int32_t &globalX, int32_t &globalY, int cursorW, int cursorH)
{
    if (globalX < 0) {
        globalX = 0;
    }

    if (globalY < 0) {
        globalY = 0;
    }

    if (logicalDisplays_.size() == 0) {
        return;
    }

    if ((globalX + cursorW) > logicalDisplays_[0].width ) {
        globalX = logicalDisplays_[0].width - cursorW;
    }

    if ((globalY + cursorH) > logicalDisplays_[0].height ) {
        globalY = logicalDisplays_[0].height - cursorH;
    }
}

int32_t OHOS::MMI::InputWindowsManager::UpdateMouseTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    return -1;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGE("UpdateMouseTarget begin ...");
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!CheckDisplayIdIfExist(displayId)) {
        MMI_LOGE("this displayId:%{public}d is not exist", displayId);
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_LOGE("FindWindow failed, can't find pointer item");
        return RET_ERR;
    }
    LogicalDisplayInfo logicalDisplayInfo;
    if (!GetLogicalDisplayById(displayId, logicalDisplayInfo)) {
        MMI_LOGE("DisplayIdGetLogicalDisplay failed");
        return RET_ERR;
    }
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    FixCursorPosition(globalX, globalY, IMAGE_SIZE, IMAGE_SIZE);
    //DrawWgr->DrawPointer(displayId, globalX, globalY);
    WindowInfo *focusWindos = nullptr;
    for (auto it : logicalDisplayInfo.windowsInfo_) {
        if (isTouchWindow(globalX, globalY, it)) {
            focusWindos = &it;
            break;
        }
    }
    if (focusWindos == nullptr) {
        MMI_LOGE("find foucusWindow failed");
        return RET_ERR;
    }
    pointerEvent->SetTargetWindowId(focusWindos->id);
    pointerEvent->SetAgentWindowId(focusWindos->agentWindowId);
    auto fd = udsServer_->GetFdByPid(focusWindos->pid);
    MMI_LOGD("the pid is :%{public}d, the fd is :%{public}d, the globalX is : %{public}d, the globalY is : %{public}d,the localX is : %{public}d, the localY is : %{public}d",
             focusWindos->pid, fd, globalX, globalY, pointerItem.GetLocalX(), pointerItem.GetLocalY());
    return fd;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchScreenTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    return -1;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!CheckDisplayIdIfExist(displayId)) {
        MMI_LOGE("this displayId is not exist");
        return -1;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_LOGE("FindWindow failed, can't find pointer item, pointerId:%{public}d", pointerId);
        return -1;
    }
    MMI_LOGD("UpdateTouchScreenTarget....displayId is : %{public}d", displayId);
    LogicalDisplayInfo logicalDisplayInfo;
    if (!GetLogicalDisplayById(displayId, logicalDisplayInfo)) {
        MMI_LOGE("DisplayIdGetLogicalDisplay failed");
        return RET_ERR;
    }
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    MMI_LOGD("UpdateTouchScreenTarget....globalX is : %{public}d, globalY is : %{public}d", globalX, globalY);
    ReviseGlobalCoordinate(globalX, globalY, logicalDisplayInfo.width, logicalDisplayInfo.height);
    auto targetWindowId = pointerEvent->GetTargetWindowId();
    MMI_LOGD("UpdateTouchScreenTarget....targetWindowId is %{public}d", targetWindowId);
    WindowInfo *touchWindow = nullptr;
    for (auto it : logicalDisplayInfo.windowsInfo_) {
        if (targetWindowId <= 0) {
            if (isTouchWindow(globalX, globalY, it)) {
                touchWindow = &it;
                break;
            }
        } else {
            if (targetWindowId == it.id) {
                touchWindow = &it;
                break;
            }
        }
    }
    if (touchWindow == nullptr) {
        MMI_LOGE("touchWindow is nullptr");
        return -1;
    }

    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    int32_t localX = globalX - touchWindow->topLeftX;
    int32_t localY = globalY - touchWindow->topLeftY;
    pointerItem.SetLocalX(localX);
    pointerItem.SetLocalY(localY);
    pointerEvent->RemovePointerItem(pointerId);
    pointerEvent->AddPointerItem(pointerItem);
    auto fd = udsServer_->GetFdByPid(touchWindow->pid);
    MMI_LOGD("the pid is :%{public}d, the fd is :%{public}d, the globalX01 is : %{public}d, "
             "the globalY01 is : %{public}d, the localX is : %{public}d, the localY is : %{public}d,"
             "the TargetWindowId is : %{public}d, the AgentWindowId is : %{public}d",
            touchWindow->pid, fd, globalX, globalY, localX, localY, pointerEvent->GetTargetWindowId(), pointerEvent->GetAgentWindowId());
    return fd;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchPadTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("touchPad event is dropped");
    return -1;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("touchPad event is dropped");
    return -1;
}

int32_t OHOS::MMI::InputWindowsManager::UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGE("UpdateMouseTarget begin ...");
    auto source = pointerEvent->GetSourceType();
    switch (source) {
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            return UpdateTouchScreenTarget(pointerEvent);
        }
        case PointerEvent::SOURCE_TYPE_MOUSE: {
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            return UpdateTouchPadTarget(pointerEvent);
        }
        default: {
            break;
        }
    }
    return -1;
}

bool OHOS::MMI::InputWindowsManager::FindWindow(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_LOGE("FindWindow failed, can't find pointer item, pointerId:%{public}d", pointerId);
        return false;
    }

    int32_t targetDisplayId = pointerEvent->GetTargetDisplayId();
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();

    MMI_LOGD("globalX:%{public}d, globalY:%{public}d", globalX, globalY);

    WindowInfo touchWindow;
    for (int32_t i = 0; i < logicalDisplays_.size(); i++) {
        if (logicalDisplays_[i].id != targetDisplayId) {
            continue;
        }
        for (int32_t j = 0; j < logicalDisplays_[i].windowsInfo_.size(); j++) {
            if (isTouchWindow(globalX, globalY, logicalDisplays_[i].windowsInfo_[j])) {
                touchWindow = logicalDisplays_[i].windowsInfo_[j];

                pointerEvent->SetTargetWindowId(touchWindow.id);
                pointerEvent->SetAgentWindowId(touchWindow.agentWindowId);
                int32_t localX = globalX - touchWindow.topLeftX;
                int32_t localY = globalY - touchWindow.topLeftY;
                pointerItem.SetLocalX(localX);
                pointerItem.SetLocalY(localY);
                pointerEvent->RemovePointerItem(pointerId);
                pointerEvent->AddPointerItem(pointerItem);

                MMI_LOGD("localX:%{public}d,localY:%{public}d", localX, localY);
                MMI_LOGD("leave");
                return true;
            }
        }
    }
    MMI_LOGD("touchWindow not found");
    return false;
}

void OHOS::MMI::InputWindowsManager::SetMouseInfo(double& x, double& y)
{
    int32_t integerX = static_cast<int32_t>(x);
    int32_t integerY = static_cast<int32_t>(y);
    MMI_LOGI("Mosue Input x = %{public}d, Mouse Input y = %{public}d", integerX, integerY);
    const std::vector<struct LogicalDisplayInfo> logicalDisplayInfo = GetLogicalDisplayInfo();
    bool isOutsideOfTopLeftX = false;
    bool isOutsideOfTopLeftY = false;
    bool isOutsideOfTopRightX = false;
    bool isOutsideOfTopRightY = false;

    if (logicalDisplayInfo.empty()) {
        MMI_LOGI("logicalDisplayInfo is empty!");
    } else {
        for (uint32_t i = 0; i < logicalDisplayInfo.size(); i++) {
            if (logicalDisplayInfo[i].id >= 0) {
                if (integerX < logicalDisplayInfo[i].topLeftX) {
                    mouseInfo_.globleX = logicalDisplayInfo[i].topLeftX;
                    mouseInfo_.localX = INVALID_LOCATION;
                    x = logicalDisplayInfo[i].topLeftX;
                    isOutsideOfTopLeftX = true;
                } else {
                    isOutsideOfTopLeftX = false;
                }
                if (integerX > (logicalDisplayInfo[i].topLeftX + logicalDisplayInfo[i].width)) {
                    mouseInfo_.globleX = logicalDisplayInfo[i].topLeftX + logicalDisplayInfo[i].width;
                    mouseInfo_.localX = INVALID_LOCATION;
                    x = logicalDisplayInfo[i].topLeftX + logicalDisplayInfo[i].width;
                    isOutsideOfTopRightX = true;
                } else {
                    isOutsideOfTopRightX = false;
                }
                if (integerY < logicalDisplayInfo[i].topLeftY) {
                    mouseInfo_.globleY = logicalDisplayInfo[i].topLeftY;
                    mouseInfo_.localY = INVALID_LOCATION;
                    y = logicalDisplayInfo[i].topLeftY;
                    isOutsideOfTopLeftY = true;
                } else {
                    isOutsideOfTopLeftY = false;
                }
                if (integerY > (logicalDisplayInfo[i].topLeftY + logicalDisplayInfo[i].height)) {
                    mouseInfo_.globleY = logicalDisplayInfo[i].topLeftY + logicalDisplayInfo[i].height;
                    mouseInfo_.localY = INVALID_LOCATION;
                    y = logicalDisplayInfo[i].topLeftY + logicalDisplayInfo[i].height;
                    isOutsideOfTopRightY = true;
                } else {
                    isOutsideOfTopRightY = false;
                }
                if ((isOutsideOfTopLeftX != true) && (isOutsideOfTopLeftY != true) &&
                    (isOutsideOfTopRightX != true) && (isOutsideOfTopRightY != true)) {
                    mouseInfo_.globleX = x;
                    mouseInfo_.globleY = y;
                    SetLocalInfo(integerX, integerY);
                    break;
                }
            } else {
                mouseInfo_.globleX = INVALID_LOCATION;
                mouseInfo_.globleY = INVALID_LOCATION;
                mouseInfo_.localX = INVALID_LOCATION;
                mouseInfo_.localY = INVALID_LOCATION;
            }
        }
    }
    MMI_LOGI("Mouse Data is : globleX = %{public}d, globleY = %{public}d, localX = %{public}d, localY = %{public}d",
        mouseInfo_.globleX, mouseInfo_.globleY, mouseInfo_.localX, mouseInfo_.localY);
}

void OHOS::MMI::InputWindowsManager::SetLocalInfo(int32_t x, int32_t y)
{
    const CLMAP<int32_t, struct WindowInfo> windowInfo = GetWindowInfo();
    bool isOutsideOfTopLeftX = false;
    bool isOutsideOfTopLeftY = false;
    bool isOutsideOfTopRightX = false;
    bool isOutsideOfTopRightY = false;

    if (windowInfo.empty()) {
        MMI_LOGI("windowInfo is empty!");
    } else {
        for (auto it = windowInfo.begin(); it != windowInfo.end(); it++) {
            if (it->second.agentWindowId >= 0) {
                if (x < it->second.topLeftX) {
                    mouseInfo_.localX = INVALID_LOCATION;
                    isOutsideOfTopLeftX = true;
                } else {
                    isOutsideOfTopLeftX = false;
                }
                if (x > (it->second.topLeftX + it->second.width)) {
                    mouseInfo_.localX = INVALID_LOCATION;
                    isOutsideOfTopLeftY = true;
                } else {
                    isOutsideOfTopLeftY = false;
                }
                if (y < it->second.topLeftY) {
                    mouseInfo_.localY = INVALID_LOCATION;
                    isOutsideOfTopRightX = true;
                } else {
                    isOutsideOfTopRightX = false;
                }
                if (y > (it->second.topLeftY + it->second.height)) {
                    mouseInfo_.localY = INVALID_LOCATION;
                    isOutsideOfTopRightY = true;
                } else {
                    isOutsideOfTopRightY = false;
                }
                if ((isOutsideOfTopLeftX != true) && (isOutsideOfTopLeftY != true) &&
                    (isOutsideOfTopRightX != true) && (isOutsideOfTopRightY != true)) {
                    mouseInfo_.localX = x - it->second.topLeftX;
                    mouseInfo_.localY = y - it->second.topLeftY;
                    break;
                }
            }
        }
    }
}

MouseInfo OHOS::MMI::InputWindowsManager::GetMouseInfo()
{
    return mouseInfo_;
}