/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "server_msg_handler.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class ServerMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class ServerMsgHandlerUnitTest : public ServerMsgHandler {
public:
    int32_t OnInjectKeyEventTest(SessionPtr sess, std::shared_ptr<KeyEvent> keyEvent)
    {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        return OnInjectKeyEvent(keyEvent);
#else
        return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    }
};
} // namespace MMI
} // namespace OHOS
