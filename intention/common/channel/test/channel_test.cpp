/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#define private public
#define protected public

#include <gtest/gtest.h>

#include "channel.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "ChannelTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t DEFAULT_WAIT_TIME { 10 };
}
using namespace testing::ext;

class ChannelTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ChannelTest001
 * @tc.desc: test channel throuthput when sending speed is greater than receiving speed.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelTest, ChannelTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto [sender, receiver] = Channel<size_t>::OpenChannel();
    constexpr size_t count = Channel<size_t>::QUEUE_CAPACITY;
    receiver.Enable();

    std::thread worker([sender = sender, count]() mutable {
        for (size_t index = 0; index < count; ++index) {
            EXPECT_EQ(sender.Send(index), Channel<size_t>::NO_ERROR);
        }
    });
    for (size_t expected = 0; expected < count;) {
        size_t received = receiver.Receive();
        EXPECT_EQ(received, expected);
        if ((++expected % 10) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_WAIT_TIME));
        }
    }
    if (worker.joinable()) {
        worker.join();
    }
}

/**
 * @tc.name: ChannelTest002
 * @tc.desc: test channel throuthput when sending speed is less than receiving speed.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelTest, ChannelTest002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto [sender, receiver] = Channel<size_t>::OpenChannel();
    constexpr size_t count = Channel<size_t>::QUEUE_CAPACITY;
    receiver.Enable();

    std::thread worker([sender = sender, count]() mutable {
        for (size_t index = 0; index < count;) {
            EXPECT_EQ(sender.Send(index), Channel<size_t>::NO_ERROR);
            if ((++index % 10) == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_WAIT_TIME));
            }
        }
    });
    for (size_t expected = 0; expected < count; ++expected) {
        size_t received = receiver.Receive();
        ASSERT_EQ(received, expected);
    }
    if (worker.joinable()) {
        worker.join();
    }
}

/**
 * @tc.name: ChannelTest003
 * @tc.desc: Disallow sending of events when channel is inactive.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelTest, ChannelTest003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto [sender, receiver] = Channel<size_t>::OpenChannel();
    const size_t data = 1;
    EXPECT_EQ(sender.Send(data), Channel<size_t>::INACTIVE_CHANNEL);
}

/**
 * @tc.name: ChannelTest004
 * @tc.desc: Disallow sending of events when queue is full.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelTest, ChannelTest004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto [sender, receiver] = Channel<size_t>::OpenChannel();
    size_t data = 1;
    receiver.Enable();

    for (size_t index = 0; index < Channel<size_t>::QUEUE_CAPACITY; ++index) {
        EXPECT_EQ(sender.Send(data++), Channel<size_t>::NO_ERROR);
    };
    EXPECT_EQ(sender.Send(data), Channel<size_t>::QUEUE_IS_FULL);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
