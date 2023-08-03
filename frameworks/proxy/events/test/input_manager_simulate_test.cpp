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
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerTest" };
constexpr int32_t TIME_WAIT_FOR_OP = 100;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t DEFAULT_POINTER_ID = 0;
constexpr int32_t DEFAULT_DEVICE_ID = 0;
constexpr int32_t INDEX_FIRST = 1;
constexpr int32_t INDEX_SECOND = 2;
constexpr int32_t INDEX_THIRD = 3;
constexpr int32_t KEY_REPEAT_DELAY = 350;
constexpr int32_t KEY_REPEAT_RATE = 60;
} // namespace

class InputManagerPointerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    std::string GetEventDump();
};
} // namespace MMI
} // namespace OHOS