/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <cstdio>

#include "event_log_helper.h"
#include "event_util_test.h"
#include "input_handler_type.h"
#include "input_manager_impl.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "pixel_map.h"
#include "system_info.h"
#include "util.h"
#include "scene_board_judgement.h"

namespace OHOS {
namespace MMI {
std::shared_ptr<PointerEvent> InputManagerTest::SetupPointerEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetPressure(5);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    item.SetPointerId(1);
    item.SetDisplayX(610);
    item.SetDisplayY(910);
    item.SetPressure(7);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}
} // namespace MMI
} // namespace OHOS