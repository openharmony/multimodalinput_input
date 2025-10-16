/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "pointer_style.h"
#include "customcursorparcel_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "image_source.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "CustomCursorParcelFuzzTest"

namespace OHOS {
namespace MMI {
constexpr int32_t MOUSE_ICON_SIZE = 64;
std::unique_ptr<OHOS::Media::PixelMap> SetMouseIconTest(const std::string iconPath)
{
    OHOS::Media::SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(iconPath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    MMI_HILOGD("Get supported format ret:%{public}u", ret);

    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {.width = MOUSE_ICON_SIZE, .height = MOUSE_ICON_SIZE};

    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    CHKPL(pixelMap);
    return pixelMap;
}

bool CustomCursorParcelFuzzTest(const uint8_t *data, size_t size)
{
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    FuzzedDataProvider provider(data, size);
    int32_t focusX = provider.ConsumeIntegral<int32_t>();
    int32_t focusY = provider.ConsumeIntegral<int32_t>();
    CustomCursorParcel cursorParcel(static_cast<void*>(pixelMap.get()), focusX, focusY);

    Parcel parcel;
    cursorParcel.Marshalling(parcel);
    cursorParcel.ReadFromParcel(parcel);
    cursorParcel.Unmarshalling(parcel);
    MMI_HILOGD("CustomCursorParcelFuzzTest");
    return true;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::CustomCursorParcelFuzzTest(data, size);
    return 0;
}
