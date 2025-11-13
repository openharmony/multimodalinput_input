/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INPUT_MANAGER_UTIL_H
#define INPUT_MANAGER_UTIL_H

#include "image_source.h"
#include "pixel_map.h"

#include "i_input_event_consumer.h"
#include "input_event.h"
#include "input_handler_type.h"
#include "key_event.h"
#include "key_option.h"
#include "mmi_log.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class InputManagerUtil {
public:
    static std::shared_ptr<KeyOption> InitOption(
        const std::set<int32_t> &preKeys, int32_t finalKey, bool isFinalKeyDown, int32_t duration);
    static std::shared_ptr<PointerEvent> SetupPointerEvent001();
    static std::shared_ptr<PointerEvent> SetupPointerEvent002();
    static std::shared_ptr<PointerEvent> SetupPointerEvent003();
    static std::shared_ptr<PointerEvent> SetupPointerEvent005();
    static std::shared_ptr<PointerEvent> SetupPointerEvent006();
    static std::shared_ptr<PointerEvent> SetupPointerEvent007();
    static std::shared_ptr<PointerEvent> SetupPointerEvent009();
    static std::shared_ptr<PointerEvent> SetupPointerEvent010();
    static std::shared_ptr<PointerEvent> SetupPointerEvent011();
    static std::shared_ptr<PointerEvent> SetupPointerEvent012();
    static std::shared_ptr<PointerEvent> SetupPointerEvent013();
    static std::shared_ptr<PointerEvent> SetupPointerEvent014();
    static std::shared_ptr<PointerEvent> SetupPointerEvent015();
#ifdef OHOS_BUILD_ENABLE_JOYSTICK
    static std::shared_ptr<PointerEvent> SetupPointerEvent016();
#endif // OHOS_BUILD_ENABLE_JOYSTICK
    static std::shared_ptr<PointerEvent> SetupMouseEvent001();
    static std::shared_ptr<PointerEvent> SetupMouseEvent002();
    static std::shared_ptr<PointerEvent> SetupTouchScreenEvent001();
    static std::shared_ptr<PointerEvent> SetupTouchScreenEvent002();
    static void SetPointerItem(PointerEvent::PointerItem &item, int32_t pointerId);
    static void PrintPointerEventId(std::shared_ptr<PointerEvent> pointerEvent);
    static std::shared_ptr<PointerEvent> SetupSimulateEvent001();
    static std::shared_ptr<PointerEvent> SetupSimulateEvent002();
    static std::shared_ptr<PointerEvent> SetupSimulateEvent003();
    static std::shared_ptr<PointerEvent> SetupSimulateEvent004();
    static std::shared_ptr<PointerEvent> SetupSimulateEvent005();
    static std::shared_ptr<PointerEvent> SetupSimulateEvent006();
    static std::shared_ptr<PointerEvent> SetupSimulateEvent007();
    static std::shared_ptr<PointerEvent> SetupSimulateEvent008();
    static std::shared_ptr<KeyEvent> SetupKeyEvent001();
    static std::shared_ptr<KeyEvent> SetupKeyEvent002();
    static std::shared_ptr<KeyEvent> SetupKeyEvent003();
    static std::shared_ptr<PointerEvent> TestMarkConsumedStep1();
    static std::shared_ptr<PointerEvent> TestMarkConsumedStep2();
    static std::unique_ptr<OHOS::Media::PixelMap> SetMouseIconTest(const std::string iconPath);
    static void TestMarkConsumedStep3(int32_t monitorId, int32_t eventId);
    static void TestMarkConsumedStep4();
    static void TestMarkConsumedStep5();
    static void TestMarkConsumedStep6();
    static int32_t TestAddMonitor(std::shared_ptr<IInputEventConsumer> consumer);
    static void TestRemoveMonitor(int32_t monitorId);
    static void TestMarkConsumed(int32_t monitorId, int32_t eventId);
    static void TestMonitor(int32_t monitorId, std::shared_ptr<PointerEvent> pointerEvent);
    static void TestInterceptorIdAndPointerEvent(int32_t interceptorId, std::shared_ptr<PointerEvent> pointerEvent);
    static void TestInterceptorId(int32_t interceptorId1, int32_t interceptorId2);
    static std::shared_ptr<PointerEvent> SetupTabletToolEvent001();
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_MANAGER_UTIL_H