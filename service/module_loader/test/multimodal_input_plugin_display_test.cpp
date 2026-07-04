/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include <atomic>
#include <memory>

#include <gtest/gtest.h>

#include "mmi_log.h"
#include "multimodal_input_plugin_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputPluginDisplayTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class MultimodalInputPluginDisplayTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputPlugin_RegisterDisplayChangeCallback_001
 * @tc.desc: Registering a valid callback returns a strictly-positive id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_RegisterDisplayChangeCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    int32_t callbackId = plugin->RegisterDisplayChangeCallback([]() {});
    EXPECT_GT(callbackId, 0);
}

/**
 * @tc.name: InputPlugin_RegisterDisplayChangeCallback_002
 * @tc.desc: Registering a null callback fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_RegisterDisplayChangeCallback_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    int32_t callbackId = plugin->RegisterDisplayChangeCallback(nullptr);
    EXPECT_LT(callbackId, 0);
}

/**
 * @tc.name: InputPlugin_RegisterDisplayChangeCallback_003
 * @tc.desc: Multiple registrations yield unique ids.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_RegisterDisplayChangeCallback_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    int32_t id1 = plugin->RegisterDisplayChangeCallback([]() {});
    int32_t id2 = plugin->RegisterDisplayChangeCallback([]() {});
    EXPECT_GT(id1, 0);
    EXPECT_GT(id2, 0);
    EXPECT_NE(id1, id2);
}

/**
 * @tc.name: InputPlugin_UnregisterDisplayChangeCallback_001
 * @tc.desc: Unregistering a previously registered id succeeds.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_UnregisterDisplayChangeCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    int32_t callbackId = plugin->RegisterDisplayChangeCallback([]() {});
    ASSERT_GE(callbackId, 0);
    EXPECT_TRUE(plugin->UnregisterDisplayChangeCallback(callbackId));
}

/**
 * @tc.name: InputPlugin_UnregisterDisplayChangeCallback_002
 * @tc.desc: Unregistering an unknown id fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_UnregisterDisplayChangeCallback_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    EXPECT_FALSE(plugin->UnregisterDisplayChangeCallback(-1));
    EXPECT_FALSE(plugin->UnregisterDisplayChangeCallback(999999));
}

/**
 * @tc.name: InputPlugin_UnregisterDisplayChangeCallback_003
 * @tc.desc: A callback id can only be unregistered once; a second unregister fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_UnregisterDisplayChangeCallback_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    int32_t callbackId = plugin->RegisterDisplayChangeCallback([]() {});
    ASSERT_GT(callbackId, 0);
    EXPECT_TRUE(plugin->UnregisterDisplayChangeCallback(callbackId));
    EXPECT_FALSE(plugin->UnregisterDisplayChangeCallback(callbackId));
}

/**
 * @tc.name: InputPluginManager_DisplayChangeNotify_001
 * @tc.desc: A callback registered via the plugin fires when NotifyDisplayChange runs, and
 *          stops firing after it is unregistered (AC-1.2 / AC-5.3 dispatch path).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPluginManager_DisplayChangeNotify_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);

    std::atomic<int> counter { 0 };
    int32_t id = plugin->RegisterDisplayChangeCallback([&counter]() { counter++; });
    ASSERT_GT(id, 0);

    auto *mgr = InputPluginManager::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->NotifyDisplayChange();
    EXPECT_EQ(counter.load(), 1);

    ASSERT_TRUE(plugin->UnregisterDisplayChangeCallback(id));
    mgr->NotifyDisplayChange();
    EXPECT_EQ(counter.load(), 1);
}

/**
 * @tc.name: InputPluginManager_DisplayChangeNotify_002
 * @tc.desc: Callbacks from different plugins all dispatch from the central registry, and
 *          unregistering one leaves the others firing (AC-1.2 / AC-5.3 multi-plugin).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPluginManager_DisplayChangeNotify_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pluginA = std::make_shared<InputPlugin>(nullptr);
    auto pluginB = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(pluginA, nullptr);
    ASSERT_NE(pluginB, nullptr);

    std::atomic<int> counterA { 0 };
    std::atomic<int> counterB { 0 };
    int32_t idA = pluginA->RegisterDisplayChangeCallback([&counterA]() { counterA++; });
    int32_t idB = pluginB->RegisterDisplayChangeCallback([&counterB]() { counterB++; });
    ASSERT_GT(idA, 0);
    ASSERT_GT(idB, 0);

    auto *mgr = InputPluginManager::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->NotifyDisplayChange();
    EXPECT_EQ(counterA.load(), 1);
    EXPECT_EQ(counterB.load(), 1);

    ASSERT_TRUE(pluginA->UnregisterDisplayChangeCallback(idA));
    mgr->NotifyDisplayChange();
    EXPECT_EQ(counterA.load(), 1);
    EXPECT_EQ(counterB.load(), 2);
}

/**
 * @tc.name: InputPlugin_GetDisplayGroupInfos_001
 * @tc.desc: GetDisplayGroupInfos returns a vector without crashing.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_GetDisplayGroupInfos_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    EXPECT_NO_FATAL_FAILURE({
        auto groups = plugin->GetDisplayGroupInfos();
        (void)groups;
    });
}

/**
 * @tc.name: InputPlugin_GetInputDeviceInfos_001
 * @tc.desc: GetInputDeviceInfos returns a vector without crashing.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPlugin_GetInputDeviceInfos_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    EXPECT_NO_FATAL_FAILURE({
        auto devices = plugin->GetInputDeviceInfos();
        (void)devices;
    });
}

/**
 * @tc.name: InputPluginManager_NotifyDisplayChange_Direct_001
 * @tc.desc: NotifyDisplayChange directly invokes registered display callbacks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPluginManager_NotifyDisplayChange_Direct_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::atomic<int> counter { 0 };
    auto plugin = std::make_shared<InputPlugin>(nullptr);
    ASSERT_NE(plugin, nullptr);
    int32_t id = plugin->RegisterDisplayChangeCallback([&counter]() { counter++; });
    ASSERT_GT(id, 0);

    EXPECT_NO_FATAL_FAILURE(manager->NotifyDisplayChange());
    EXPECT_EQ(counter.load(), 1);

    ASSERT_TRUE(plugin->UnregisterDisplayChangeCallback(id));
}

/**
 * @tc.name: InputPluginManager_NotifyDisplayChange_001
 * @tc.desc: NotifyDisplayChange completes without deadlock even with no callbacks registered.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPluginManager_NotifyDisplayChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    EXPECT_NO_FATAL_FAILURE(manager->NotifyDisplayChange());
}

/**
 * @tc.name: InputPluginManager_NotifyDisplayChange_002
 * @tc.desc: NotifyDisplayChange can be called directly without posting to a queue.
 * @tc.type: FUNC
 * @tc.require:
 *
 * Note: NotifyDisplayChange collects callbacks from plugins already added to the manager's
 * stages (via AddPluginToStages). A standalone InputPlugin is not in any stage, so this
 * case only asserts the manager path completes without crashing; end-to-end delivery of
 * the callback to a staged plugin requires the LoadPlugin path.
 */
HWTEST_F(MultimodalInputPluginDisplayTest, InputPluginManager_NotifyDisplayChange_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    EXPECT_NO_FATAL_FAILURE({
        manager->NotifyDisplayChange();
    });
}
} // namespace MMI
} // namespace OHOS
