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
#ifndef OHOS_INPUT_WINDOWS_MANAGER_H
#define OHOS_INPUT_WINDOWS_MANAGER_H

#include <vector>
#include "c_singleton.h"
#include "uds_server.h"

#ifdef OHOS_WESTEN_MODEL
extern "C" {
#include <screen_info.h>
}
#else
struct SurfaceInfo {
    int surfaceId;
    int dstX;
    int dstY;
    int dstW;
    int dstH;
    int srcX;
    int srcY;
    int srcW;
    int srcH;
    double opacity;
    int visibility; // 0 or 1
    int onLayerId;
};

struct LayerInfo {
    int layerId;
    int dstX;
    int dstY;
    int dstW;
    int dstH;
    int srcX;
    int srcY;
    int srcW;
    int srcH;
    double opacity;
    int visibility; // 0 or 1
    int onScreenId;
    int nSurfaces;
    struct SurfaceInfo** surfaces;
};

struct ScreenInfo {
    int screenId;
    char* connectorName;
    int width;
    int height;
    int nLayers;
    struct LayerInfo** layers;
};

struct SeatInfo {
    char* seatName;
    int deviceFlags;
    int focusWindowId;
};

struct SeatInfo** GetSeatsInfo(void);
struct ScreenInfo** GetScreensInfo(void);
void FreeSurfaceInfo(struct SurfaceInfo* pSurface);
void FreeLayerInfo(struct LayerInfo* pLayer);
void FreeScreenInfo(struct ScreenInfo* pScreen);
void FreeScreensInfo(struct ScreenInfo** screens);
void FreeSeatsInfo(struct SeatInfo** seats);
using SeatInfoChangeListener = void (*)();
using ScreenInfoChangeListener = void (*)();
void SetSeatListener(const SeatInfoChangeListener listener);
void SetScreenListener(const ScreenInfoChangeListener listener);

struct libinput_event;
typedef void (*LibInputEventListener)(struct libinput_event* event);
namespace OHOS {
namespace MMI {
void SetLibInputEventListener(const LibInputEventListener listener);
}
}
#endif

struct MMISurfaceInfo : public SurfaceInfo {
    int32_t screenId;
};

namespace OHOS {
namespace MMI {
class InputWindowsManager : public CSingleton<InputWindowsManager> {
public:
    InputWindowsManager();
    virtual ~InputWindowsManager();

    bool Init(UDSServer& udsServer);
    void UpdateSeatsInfo();
    void UpdateScreensInfo();

    const ScreenInfo* GetScreenInfo(int32_t screenId);
    const LayerInfo* GetLayerInfo(int32_t layerId);
    const MMISurfaceInfo* GetSurfaceInfo(int32_t sufaceId);
    bool CheckFocusSurface(double x, double y, const MMISurfaceInfo& info) const;
    const MMISurfaceInfo* GetTouchSurfaceInfo(double x, double y);
    void TransfromToSurfaceCoordinate(double& x, double& y, const MMISurfaceInfo& info, bool debug = false);

    bool GetTouchSurfaceId(const double x, const double y, std::vector<int32_t>& ids);

    const std::vector<ScreenInfo>& GetScreenInfo() const;

    const CLMAP<int32_t, LayerInfo>& GetLayerInfo() const;

    const CLMAP<int32_t, MMISurfaceInfo>& GetSurfaceInfo() const;

    void InsertSurfaceInfo(const MMISurfaceInfo& tmpSurfaceInfo);

    void PrintAllNormalSurface();

    void SetFocusSurfaceId(int32_t id);
    void SetTouchFocusSurfaceId(int32_t id);

    int32_t GetFocusSurfaceId() const;
    int32_t GetTouchFocusSurfaceId() const;

    size_t GetSurfaceIdList(IdsList& ids);
    std::string GetSurfaceIdListString();
    void Clear();
    void Dump(int32_t fd);

private:
    void SetFocusId(int32_t id);
    void PrintDebugInfo();
    void SaveScreenInfoToMap(const ScreenInfo **screen_info);
    bool FindSurfaceByCoordinate(double x, double y, const SurfaceInfo& pstrSurface);

private:
    std::mutex mu_;
    struct SeatInfo** seatsInfo_ = nullptr;
    struct ScreenInfo **screensInfo_ = nullptr;
    int32_t focusInfoID_ = 0;
    int32_t touchFocusId_ = 0;
    IdsList surfacesList_; // surfaces ids list
    std::vector<struct ScreenInfo> screenInfoVec_ = {};
    CLMAP<int32_t, struct LayerInfo> layers_ = {};
    CLMAP<int32_t, struct MMISurfaceInfo> surfaces_ = {};
    UDSServer* udsServer_ = nullptr;
};
}
}

#define WinMgr OHOS::MMI::InputWindowsManager::GetInstance()
#endif
