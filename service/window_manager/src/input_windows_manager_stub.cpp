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


namespace OHOS::MMI {
namespace {
[[maybe_unused]]static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputWindowsManagerStub"};
}
}

using namespace OHOS::MMI;

#ifndef OHOS_WESTEN_MODEL
#define MAX_LENGTH 1024

struct SeatInfo** GetSeatsInfo()
{
    MMI_LOGT("GetSeatsInfo...");
    const int32_t TEST_VAL = 2;
    const int32_t TEST_SEATNAME_SIZE = 32;
    auto setInfo = static_cast<SeatInfo**>(malloc(sizeof(SeatInfo*) * TEST_VAL));
    CHKF(setInfo, OHOS::MALLOC_FAIL);
    setInfo[0] = static_cast<SeatInfo*>(malloc(sizeof(SeatInfo)));
    CHKF(setInfo[0], OHOS::MALLOC_FAIL);
    setInfo[0]->seatName = (char*)malloc(TEST_SEATNAME_SIZE);
    CHKF(setInfo[0]->seatName, OHOS::MALLOC_FAIL);
    CHKF(strcpy_s(setInfo[0]->seatName, TEST_SEATNAME_SIZE, "seat0") == EOK, OHOS::SEC_STRCPY_FAIL);
    setInfo[0]->deviceFlags = -1;
    setInfo[0]->focusWindowId = 0;
    setInfo[1] = nullptr;
    return setInfo;
}

struct ScreenInfo** GetScreensInfo()
{
    MMI_LOGT("GetScreensInfo...");
    const int32_t TEST_VAL = 2;
    const int32_t TEST_LAYER_ID = 2;
    const int32_t TEST_WIDTH = 1920;
    const int32_t TEST_HEIGHT = 1080;
    const int32_t TEST_SURFACE_ID = 3;
    const int32_t TEST_ON_LAYER_ID = 2;

    auto screenInfo = static_cast<ScreenInfo**>(malloc(sizeof(ScreenInfo*) * TEST_VAL));
    CHKF(screenInfo, OHOS::MALLOC_FAIL);
    screenInfo[0] = static_cast<ScreenInfo*>(malloc(sizeof(ScreenInfo)));
    CHKF(screenInfo[0], OHOS::MALLOC_FAIL);
    CHKF(memset_s(screenInfo[0], sizeof(ScreenInfo), 0, sizeof(ScreenInfo)) == EOK, OHOS::MEMSET_SEC_FUN_FAIL);
    *screenInfo[0] = {.screenId = 1, .connectorName = nullptr, .width = TEST_WIDTH, .height = TEST_HEIGHT,
        .nLayers = 1, .layers = static_cast<LayerInfo**>(malloc(sizeof(struct LayerInfo*)))
    };
    screenInfo[1] = nullptr;

    LayerInfo** layerInfo = screenInfo[0]->layers;
    layerInfo[0] = static_cast<LayerInfo*>(malloc(sizeof(LayerInfo)));
    CHKF(layerInfo[0], OHOS::MALLOC_FAIL);
    CHKF(memset_s(layerInfo[0], sizeof(LayerInfo), 0, sizeof(LayerInfo)) == EOK, OHOS::MEMSET_SEC_FUN_FAIL);
    layerInfo[0]->layerId = TEST_LAYER_ID;
    layerInfo[0]->onScreenId = 1;
    layerInfo[0]->nSurfaces = 1;
    layerInfo[0]->surfaces = static_cast<SurfaceInfo**>(malloc(sizeof(SurfaceInfo*)));
    CHKF(layerInfo[0]->surfaces, OHOS::MALLOC_FAIL);
    layerInfo[0]->srcW = TEST_WIDTH;
    layerInfo[0]->srcH = TEST_HEIGHT;
    layerInfo[0]->dstW = TEST_WIDTH;
    layerInfo[0]->dstH = TEST_HEIGHT;

    SurfaceInfo** surfaceInfo = layerInfo[0]->surfaces;
    surfaceInfo[0] = static_cast<SurfaceInfo*>(malloc(sizeof(SurfaceInfo)));
    CHKF(surfaceInfo[0], OHOS::MALLOC_FAIL);
    CHKF(memset_s(surfaceInfo[0], sizeof(SurfaceInfo), 0, sizeof(SurfaceInfo)) == EOK, OHOS::MEMSET_SEC_FUN_FAIL);
    surfaceInfo[0]->surfaceId = TEST_SURFACE_ID;
    surfaceInfo[0]->onLayerId = TEST_ON_LAYER_ID;
    surfaceInfo[0]->srcW = TEST_WIDTH;
    surfaceInfo[0]->srcH = TEST_HEIGHT;
    surfaceInfo[0]->dstW = TEST_WIDTH;
    surfaceInfo[0]->dstH = TEST_HEIGHT;
    return screenInfo;
}

void FreeSurfaceInfo(const struct SurfaceInfo* pSurface)
{
    MMI_LOGT("FreeSurfaceInfo...");
    if (pSurface) {
        free(const_cast<SurfaceInfo*>(pSurface));
    }
}

void FreeLayerInfo(const struct LayerInfo* pLayer)
{
    MMI_LOGT("FreeLayerInfo...");
    if (pLayer) {
        if (pLayer->surfaces) {
            for (int i = 0; i < pLayer->nSurfaces; i++) {
                FreeSurfaceInfo(const_cast<SurfaceInfo*>(pLayer->surfaces[i]));
            }
            free(pLayer->surfaces);
        }
        free(const_cast<LayerInfo*>(pLayer));
    }
}

void FreeScreenInfo(const struct ScreenInfo* pScreen)
{
    MMI_LOGT("FreeScreenInfo...");
    if (pScreen) {
        if (pScreen->layers) {
            for (int i = 0; i < pScreen->nLayers; i++) {
                FreeLayerInfo(const_cast<LayerInfo*>(pScreen->layers[i]));
            }
            free(pScreen->layers);
        }
        if (pScreen->connectorName) {
            free(pScreen->connectorName);
        }
        free(const_cast<ScreenInfo*>(pScreen));
    }
}

void FreeScreensInfo(struct ScreenInfo** screens)
{
    MMI_LOGT("FreeScreensInfo...");
    if (!screens) {
        MMI_LOGE("screens is null.");
        return;
    }
    for (int i = 0; screens[i]; i++) {
        FreeScreenInfo(screens[i]);
    }
    free(screens);
}

void FreeSeatsInfo(struct SeatInfo** seats)
{
    MMI_LOGT("FreeSeatsInfo...");
    if (!seats) {
        MMI_LOGE("seats is null.");
        return;
    }
    for (int i = 0; seats[i]; i++) {
        if (seats[i]->seatName) {
            free(seats[i]->seatName);
        }
        free(seats[i]);
    }
    free(seats);
}

void SetSeatListener(const SeatInfoChangeListener listener)
{
    MMI_LOGT("SetSeatListener...");
}

void SetScreenListener(const ScreenInfoChangeListener listener)
{
    MMI_LOGT("SetScreenListener...");
}

void OHOS::MMI::SetLibInputEventListener(const LibInputEventListener listener)
{
    MMI_LOGT("SetLibInputEventListener...");
}
#endif
