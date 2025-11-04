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

#include <fcntl.h>
#include <fstream>
#include <cJSON.h>
#include <gtest/gtest.h>

#include "config_policy_utils.h"
#include "init_param.h"

#include "define_multimodal.h"
#include "key_shortcut_manager.h"
#include "local_hotkey_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LocalHotKeyHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
char g_cfgName[] { "custom_local_hot_keys.json" };
constexpr char g_dumpName[] { "local_hot_keys_dump.json" };
constexpr std::uintmax_t MAX_SIZE_OF_LOCAL_HOT_KEYS_CONFIG { 8192 };
constexpr size_t SINGLE_ITEM { 1 };
constexpr size_t TWO_ITEMS { 2 };
}
using namespace testing::ext;
using namespace testing;

#define LOCAL_HOT_KEY_KEYCODE           0x100
#define LOCAL_HOT_KEY_ACTION            0x200
#define LOCAL_HOT_KEY_MASK  (KeyShortcutManager::SHORTCUT_MODIFIER_MASK | LOCAL_HOT_KEY_KEYCODE | LOCAL_HOT_KEY_ACTION)

struct LocalHotKeyInfo {
    double keyCode_ { KeyEvent::KEYCODE_UNKNOWN };
    uint32_t modifiers_ { 0U };
    uint32_t optionalModifiers_ { 0U };
    uint32_t mask_ { LOCAL_HOT_KEY_MASK };
    LocalHotKeyAction action_ { LocalHotKeyAction::INTERCEPT };
};

struct InputEventHandlerMock : public IInputEventHandler {
    InputEventHandlerMock() = default;
    virtual ~InputEventHandlerMock() = default;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override
    {
        auto event = KeyEvent::Clone(keyEvent);
        if (event != nullptr) {
            events_.push_back(event);
        }
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent>) override {}
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent>) override {}
#endif // OHOS_BUILD_ENABLE_TOUCH

    std::vector<std::shared_ptr<KeyEvent>> events_;
};

class LocalHotKeyHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown();

private:
    void SerializeLocalHotKeysConfig(cJSON *jsonConfig);
    void BuildLocalHotKeysConfig(const std::vector<LocalHotKeyInfo> &localHotKeys);
    void WriteLocalHotKey(cJSON *jsonLocalHotKeys, const LocalHotKeyInfo &localHotKeys);
    cJSON* WriteLocalHotKeyModifiers(const LocalHotKeyInfo &localHotKey);
    cJSON* WriteLocalHotKeyAction(const LocalHotKeyInfo &localHotKey);
    void BuildLocalHotKeysConfig103();
    void BuildLocalHotKeysConfig104();
    void BuildLocalHotKeysConfig105();
    void BuildLocalHotKeysConfig106();
    void BuildLocalHotKeysConfig107();
    void BuildLocalHotKeysConfig108();
    void BuildLocalHotKeysConfig109();
    void BuildLocalHotKeysConfig110();
    void BuildLocalHotKeysConfig111();
    void BuildLocalHotKeysConfig112();
    void BuildLocalHotKeysConfig113();
    void BuildLocalHotKeysConfig114();
    void BuildLocalHotKeysConfig115();
    void BuildLocalHotKeysConfig116();
    std::shared_ptr<KeyEvent> BuildKeyEvent0201();
    std::shared_ptr<KeyEvent> BuildKeyEvent0301();
    void DumpLocalHotKeys();
    void CheckLocalHotKeys(const std::vector<std::string> &expected);
    void DumpLocalHotKeys001();
    void DumpLocalHotKeys002();
    void DumpLocalHotKeys003();
    void DumpLocalHotKeys004();
    void DumpLocalHotKeys005();
    void DumpLocalHotKeys006();
    void DumpLocalHotKeys007();
};

void LocalHotKeyHandlerTest::SetUp()
{
    LocalHotKeyHandler::steward_.localHotKeys_.clear();
    LocalHotKeyHandler::steward_.systemHotKeys_.clear();
}

void LocalHotKeyHandlerTest::TearDown()
{
    std::filesystem::remove(g_cfgName);
    std::filesystem::remove(g_dumpName);
}

void LocalHotKeyHandlerTest::SerializeLocalHotKeysConfig(cJSON *jsonConfig)
{
    CHKPV(jsonConfig);
    auto sConfig = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonConfig),
        [](char *object) {
            if (object != nullptr) {
                cJSON_free(object);
            }
        });
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << sConfig.get();
        ofs.flush();
        ofs.close();
    }
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig(const std::vector<LocalHotKeyInfo> &localHotKeys)
{
    auto jsonConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonConfig);
    auto jsonLocalHotKeys = cJSON_CreateArray();
    CHKPV(jsonLocalHotKeys);
    if (!cJSON_AddItemToObject(jsonConfig.get(), "LOCAL_HOT_KEYS", jsonLocalHotKeys)) {
        cJSON_Delete(jsonLocalHotKeys);
        return;
    }
    for (const auto &localHotKey : localHotKeys) {
        WriteLocalHotKey(jsonLocalHotKeys, localHotKey);
    }
    SerializeLocalHotKeysConfig(jsonConfig.get());
}

void LocalHotKeyHandlerTest::WriteLocalHotKey(
    cJSON *jsonLocalHotKeys, const LocalHotKeyInfo &localHotKey)
{
    auto jsonHotKey = cJSON_CreateObject();
    CHKPV(jsonHotKey);
    cJSON *jsonKeyCode = nullptr;
    cJSON *jsonModifiers = nullptr;
    cJSON *jsonAction = nullptr;

    if (localHotKey.mask_ & LOCAL_HOT_KEY_KEYCODE) {
        jsonKeyCode = cJSON_CreateNumber(localHotKey.keyCode_);
        CHKPV(jsonKeyCode);
        if (jsonKeyCode == nullptr) {
            goto CLEANUP;
        }
        if (!cJSON_AddItemToObject(jsonHotKey, "KEYCODE", jsonKeyCode)) {
            cJSON_Delete(jsonKeyCode);
            goto CLEANUP;
        }
    }
    if (localHotKey.mask_ & KeyShortcutManager::SHORTCUT_MODIFIER_MASK) {
        jsonModifiers = WriteLocalHotKeyModifiers(localHotKey);
        if (jsonModifiers == nullptr) {
            goto CLEANUP;
        }
        if (!cJSON_AddItemToObject(jsonHotKey, "MODIFIERS", jsonModifiers)) {
            cJSON_Delete(jsonModifiers);
            goto CLEANUP;
        }
    }
    if (localHotKey.mask_ & LOCAL_HOT_KEY_ACTION) {
        jsonAction = WriteLocalHotKeyAction(localHotKey);
        if (jsonAction == nullptr) {
            goto CLEANUP;
        }
        if (!cJSON_AddItemToObject(jsonHotKey, "ACTION", jsonAction)) {
            cJSON_Delete(jsonAction);
            goto CLEANUP;
        }
    }
    if (!cJSON_AddItemToArray(jsonLocalHotKeys, jsonHotKey)) {
        cJSON_Delete(jsonHotKey);
        goto CLEANUP;
    }
    return;

CLEANUP:
    cJSON_Delete(jsonHotKey);
}

cJSON* LocalHotKeyHandlerTest::WriteLocalHotKeyModifiers(const LocalHotKeyInfo &localHotKey)
{
    const std::map<std::string, uint32_t> modifierNames {
        { "CTRL", KeyShortcutManager::SHORTCUT_MODIFIER_CTRL },
        { "SHIFT", KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT },
        { "ALT", KeyShortcutManager::SHORTCUT_MODIFIER_ALT },
        { "META", KeyShortcutManager::SHORTCUT_MODIFIER_LOGO },
    };
    auto jsonModifiers = cJSON_CreateObject();
    CHKPP(jsonModifiers);

    for (const auto &[name, modifierBit] : modifierNames) {
        if ((localHotKey.mask_ & modifierBit) == 0) {
            continue;
        }
        cJSON *jsonAction = nullptr;

        if (localHotKey.optionalModifiers_ & modifierBit) {
            jsonAction = cJSON_CreateString("ANY");
        } else if (localHotKey.modifiers_ & modifierBit) {
            jsonAction = cJSON_CreateString("DOWN");
        } else {
            jsonAction = cJSON_CreateString("NONE");
        }
        if (jsonAction == nullptr) {
            goto CLEANUP;
        }
        if (!cJSON_AddItemToObject(jsonModifiers, name.c_str(), jsonAction)) {
            cJSON_Delete(jsonAction);
            goto CLEANUP;
        }
    }
    return jsonModifiers;

CLEANUP:
    cJSON_Delete(jsonModifiers);
    return nullptr;
}

cJSON* LocalHotKeyHandlerTest::WriteLocalHotKeyAction(const LocalHotKeyInfo &localHotKey)
{
    cJSON *jsonAction = nullptr;

    switch (localHotKey.action_) {
        case LocalHotKeyAction::INTERCEPT: {
            jsonAction = cJSON_CreateString("INTERCEPT");
            break;
        }
        case LocalHotKeyAction::COPY: {
            jsonAction = cJSON_CreateString("COPY");
            break;
        }
        case LocalHotKeyAction::OVER: {
            jsonAction = cJSON_CreateString("OVER");
            break;
        }
        default: {
            jsonAction = cJSON_CreateString("FUZZY");
            break;
        }
    }
    return jsonAction;
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_001
 * @tc.desc: Test LocalHotKeyHandler::LoadLocalHotKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(nullptr));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_002
 * @tc.desc: Test LocalHotKeyHandler::LoadLocalHotKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig103()
{
    const std::ofstream::pos_type tailPos { MAX_SIZE_OF_LOCAL_HOT_KEYS_CONFIG };
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs.seekp(tailPos);
        ofs << "tail";
        ofs.flush();
        ofs.close();
    }
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_003
 * @tc.desc: Test LocalHotKeyHandler::LoadLocalHotKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig103();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig104()
{
    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(LocalHotKeyInfo {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        .action_ = LocalHotKeyAction::INTERCEPT,
    });
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_004
 * @tc.desc: Failed to open config file, no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    auto uid = ::getuid();
    int32_t inputUid { 6606 };
    ::setuid(inputUid);
    BuildLocalHotKeysConfig104();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));
    EXPECT_EQ(::chmod(g_cfgName, 0), 0);
    EXPECT_EQ(::chown(g_cfgName, inputUid, inputUid), 0);

    int32_t panglaiUid { 7655 };
    ::setuid(panglaiUid);
    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_FALSE(steward.localHotKeys_.empty());
    ::setuid(uid);
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig105()
{
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << "{LOCAL_HOT_KEYS}";
        ofs.flush();
        ofs.close();
    }
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_005
 * @tc.desc: Failed to parse config file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig105();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig106()
{
    auto jsonConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateString("LOCAL_HOT_KEYS"),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonConfig);
    SerializeLocalHotKeysConfig(jsonConfig.get());
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_006
 * @tc.desc: Expect root as object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig106();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig107()
{
    auto jsonConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonConfig);
    SerializeLocalHotKeysConfig(jsonConfig.get());
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_007
 * @tc.desc: Expect 'LOCAL_HOT_KEYS' as array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig107();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig108()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    localHotKey.mask_ &= ~LOCAL_HOT_KEY_KEYCODE;

    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_008
 * @tc.desc: Expect 'LOCAL_HOT_KEY.KEYCODE'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig108();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig109()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A + 0.1,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_009
 * @tc.desc: Expect 'LOCAL_HOT_KEY.KEYCODE' as integer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig109();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig110()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_ALT_LEFT,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_010
 * @tc.desc: 'LOCAL_HOT_KEY.KEYCODE' should not be key modifier
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig110();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig111()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    localHotKey.mask_ &= ~KeyShortcutManager::SHORTCUT_MODIFIER_MASK;

    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_011
 * @tc.desc: Expect 'LOCAL_HOT_KEY.MODIFIERS'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig111();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig112()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    localHotKey.mask_ &= ~KeyShortcutManager::SHORTCUT_MODIFIER_ALT;

    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_012
 * @tc.desc: Expect all 'LOCAL_HOT_KEY.MODIFIERS' present
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig112();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig113()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    localHotKey.mask_ &= ~LOCAL_HOT_KEY_ACTION;

    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_013
 * @tc.desc: Expect 'LOCAL_HOT_KEY.ACTION'
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig113();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig114()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        .action_ = static_cast<LocalHotKeyAction>(888),
    };
    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_014
 * @tc.desc: Expect 'LOCAL_HOT_KEY.ACTION' is valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig114();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_TRUE(steward.localHotKeys_.empty());
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig115()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        .action_ = LocalHotKeyAction::OVER,
    };
    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_015
 * @tc.desc: Load correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig115();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_EQ(steward.localHotKeys_.size(), SINGLE_ITEM);
    LocalHotKey localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    auto iter = steward.localHotKeys_.find(localHotKey);
    EXPECT_NE(iter, steward.localHotKeys_.cend());
    if (iter != steward.localHotKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }
}

void LocalHotKeyHandlerTest::BuildLocalHotKeysConfig116()
{
    LocalHotKeyInfo localHotKey {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        .optionalModifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        .action_ = LocalHotKeyAction::OVER,
    };
    std::vector<LocalHotKeyInfo> localHotKeys;
    localHotKeys.emplace_back(localHotKey);
    BuildLocalHotKeysConfig(localHotKeys);
}

/**
 * @tc.name: LocalHotKeySteward_LoadLocalHotKeys_016
 * @tc.desc: Load 'ANY' modifier as expected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadLocalHotKeys_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(g_cfgName));

    BuildLocalHotKeysConfig116();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadLocalHotKeys());
    EXPECT_EQ(steward.localHotKeys_.size(), TWO_ITEMS);
    LocalHotKey localHotKey1 {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
    };
    auto iter1 = steward.localHotKeys_.find(localHotKey1);
    EXPECT_NE(iter1, steward.localHotKeys_.cend());
    if (iter1 != steward.localHotKeys_.cend()) {
        EXPECT_EQ(iter1->second, LocalHotKeyAction::OVER);
    }
    LocalHotKey localHotKey2 {
        .keyCode_ = KeyEvent::KEYCODE_A,
        .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
    };
    auto iter2 = steward.localHotKeys_.find(localHotKey2);
    EXPECT_NE(iter2, steward.localHotKeys_.cend());
    if (iter2 != steward.localHotKeys_.cend()) {
        EXPECT_EQ(iter2->second, LocalHotKeyAction::OVER);
    }
}

/**
 * @tc.name: LocalHotKeySteward_LoadSystemLocalHotKeys_001
 * @tc.desc: No system paramter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadSystemLocalHotKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<InitParamMock> mock;
    EXPECT_CALL(mock, SystemReadParam).WillOnce(Return(-1));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadSystemLocalHotKeys());
    EXPECT_TRUE(steward.systemHotKeys_.empty());
}

/**
 * @tc.name: LocalHotKeySteward_LoadSystemLocalHotKeys_002
 * @tc.desc: No system paramter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_LoadSystemLocalHotKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<InitParamMock> mock;
    std::string param { "2722;41;40;2089;2083;" };
    EXPECT_CALL(mock, SystemReadParam(NotNull(), IsNull(), NotNull())).WillOnce(DoAll(
        SetArgPointee<2>(param.size()),
        Return(0)));
    EXPECT_CALL(mock, SystemReadParam(NotNull(), NotNull(), NotNull())).WillOnce(DoAll(
        SetArrayArgument<1>(param.data(), param.data() + param.size()),
        SetArgPointee<2>(param.size()),
        Return(0)));

    LocalHotKeySteward steward;
    EXPECT_NO_FATAL_FAILURE(steward.LoadSystemLocalHotKeys());

    std::set<int32_t> keyCodes { 2722, 41, 40, 2089, 2083 };
    EXPECT_TRUE(steward.systemHotKeys_ ==  keyCodes);
}

/**
 * @tc.name: LocalHotKeySteward_QueryAction_001
 * @tc.desc: Coresponding 'ACTION' is returned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_QueryAction_001, TestSize.Level1)
{
    LocalHotKeySteward steward;
    steward.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    auto hotKeyAction = steward.QueryAction(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        });
    EXPECT_EQ(hotKeyAction, LocalHotKeyAction::COPY);
}

/**
 * @tc.name: LocalHotKeySteward_QueryAction_002
 * @tc.desc: Default 'INTERCEPT' in case of no matched local hot key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_QueryAction_002, TestSize.Level1)
{
    LocalHotKeySteward steward;
    steward.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    auto hotKeyAction = steward.QueryAction(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        });
    EXPECT_EQ(hotKeyAction, LocalHotKeyAction::INTERCEPT);
}

/**
 * @tc.name: LocalHotKeySteward_QueryAction_003
 * @tc.desc: Check system hot keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_QueryAction_003, TestSize.Level1)
{
    LocalHotKeySteward steward;
    steward.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    steward.systemHotKeys_.emplace(KeyEvent::KEYCODE_MEDIA_RECORD);
    auto hotKeyAction = steward.QueryAction(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        });
    EXPECT_EQ(hotKeyAction, LocalHotKeyAction::OVER);
}

/**
 * @tc.name: LocalHotKeySteward_QueryAction_004
 * @tc.desc: Local hot keys in priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, LocalHotKeySteward_QueryAction_004, TestSize.Level1)
{
    LocalHotKeySteward steward;
    steward.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    steward.systemHotKeys_.emplace(KeyEvent::KEYCODE_MEDIA_RECORD);
    auto hotKeyAction = steward.QueryAction(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        });
    EXPECT_EQ(hotKeyAction, LocalHotKeyAction::COPY);
}

/**
 * @tc.name: HandleEvent_001
 * @tc.desc: Test LocalHotKeyHandler::HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler handler;
    bool intercepted = false;
    EXPECT_FALSE(handler.HandleEvent(nullptr,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_FALSE(intercepted);
}

/**
 * @tc.name: HandleEvent_002
 * @tc.desc: Test LocalHotKeyHandler::HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(nullptr));

    NiceMock<InitParamMock> initParam;
    std::string param { "2722;41;40;2089;2083;" };
    EXPECT_CALL(initParam, SystemReadParam(NotNull(), IsNull(), NotNull())).WillRepeatedly(DoAll(
        SetArgPointee<2>(param.size()),
        Return(0)));
    EXPECT_CALL(initParam, SystemReadParam(NotNull(), NotNull(), NotNull())).WillRepeatedly(DoAll(
        SetArrayArgument<1>(param.data(), param.data() + param.size()),
        SetArgPointee<2>(param.size()),
        Return(0)));

    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);

    auto keyEvent = BuildKeyEvent0201();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    bool intercepted = false;

    EXPECT_TRUE(handler.HandleEvent(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_TRUE(intercepted);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::COPY);
    }
}

/**
 * @tc.name: HandleEvent_003
 * @tc.desc: Test LocalHotKeyHandler::HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(nullptr));

    NiceMock<InitParamMock> initParam;
    std::string param { "2722;41;40;2089;2083;" };
    EXPECT_CALL(initParam, SystemReadParam(NotNull(), IsNull(), NotNull())).WillRepeatedly(DoAll(
        SetArgPointee<2>(param.size()),
        Return(0)));
    EXPECT_CALL(initParam, SystemReadParam(NotNull(), NotNull(), NotNull())).WillRepeatedly(DoAll(
        SetArrayArgument<1>(param.data(), param.data() + param.size()),
        SetArgPointee<2>(param.size()),
        Return(0)));

    auto keyEvent = BuildKeyEvent0301();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    handler.consumedKeys_.emplace(KeyEvent::KEYCODE_A, LocalHotKeyAction::COPY);
    bool intercepted = false;
    EXPECT_TRUE(handler.HandleEvent(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_TRUE(intercepted);
    EXPECT_EQ(handler.consumedKeys_.find(keyEvent->GetKeyCode()), handler.consumedKeys_.end());
}

/**
 * @tc.name: HandleEvent_004
 * @tc.desc: Test LocalHotKeyHandler::HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(nullptr));

    NiceMock<InitParamMock> initParam;
    std::string param { "2722;41;40;2089;2083;" };
    EXPECT_CALL(initParam, SystemReadParam(NotNull(), IsNull(), NotNull())).WillRepeatedly(DoAll(
        SetArgPointee<2>(param.size()),
        Return(0)));
    EXPECT_CALL(initParam, SystemReadParam(NotNull(), NotNull(), NotNull())).WillRepeatedly(DoAll(
        SetArrayArgument<1>(param.data(), param.data() + param.size()),
        SetArgPointee<2>(param.size()),
        Return(0)));

    LocalHotKeyHandler::steward_.systemHotKeys_.emplace(KeyEvent::KEYCODE_MEDIA_RECORD);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_MEDIA_RECORD);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    LocalHotKeyHandler handler;
    bool intercepted = false;
    EXPECT_TRUE(handler.HandleEvent(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_FALSE(intercepted);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    intercepted = false;
    EXPECT_TRUE(handler.HandleEvent(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_FALSE(intercepted);
    EXPECT_EQ(handler.consumedKeys_.find(keyEvent->GetKeyCode()), handler.consumedKeys_.end());
}

/**
 * @tc.name: MarkProcessed_001
 * @tc.desc: Test LocalHotKeyHandler::MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, MarkProcessed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_MEDIA_RECORD);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    LocalHotKeyHandler handler;
    handler.MarkProcessed(nullptr, LocalHotKeyAction::INTERCEPT);
    EXPECT_TRUE(handler.consumedKeys_.empty());
}

/**
 * @tc.name: MarkProcessed_002
 * @tc.desc: Test LocalHotKeyHandler::MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, MarkProcessed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_P);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    LocalHotKeyHandler handler;
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::INTERCEPT);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::INTERCEPT);
    }
}

/**
 * @tc.name: MarkProcessed_003
 * @tc.desc: Test LocalHotKeyHandler::MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, MarkProcessed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_P);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    LocalHotKeyHandler handler;
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::INTERCEPT);
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::OVER);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::COPY);
    }
}

/**
 * @tc.name: MarkProcessed_004
 * @tc.desc: Test LocalHotKeyHandler::MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, MarkProcessed_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_P);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    LocalHotKeyHandler handler;
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::OVER);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }
}

/**
 * @tc.name: MarkProcessed_005
 * @tc.desc: Test LocalHotKeyHandler::MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, MarkProcessed_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_P);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    LocalHotKeyHandler handler;
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::OVER);
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::INTERCEPT);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::COPY);
    }
}

/**
 * @tc.name: MarkProcessed_006
 * @tc.desc: Test LocalHotKeyHandler::MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, MarkProcessed_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_P);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);

    LocalHotKeyHandler handler;
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::INTERCEPT);
    EXPECT_EQ(handler.consumedKeys_.find(keyEvent->GetKeyCode()), handler.consumedKeys_.cend());
}

/**
 * @tc.name: HandleLocalHotKey_001
 * @tc.desc: Test LocalHotKeyHandler::HandleLocalHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleLocalHotKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler handler;
    InputEventHandlerMock eventHandler;
    handler.HandleLocalHotKey(nullptr, eventHandler);
    EXPECT_TRUE(eventHandler.events_.empty());
}

/**
 * @tc.name: HandleLocalHotKey_002
 * @tc.desc: Test LocalHotKeyHandler::HandleLocalHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleLocalHotKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetPressed(true);
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->AddPressedKeyItems(key1);

    KeyEvent::KeyItem key2 {};
    key2.SetPressed(true);
    key2.SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->AddPressedKeyItems(key2);

    LocalHotKeyHandler handler;
    NiceMock<InputEventHandlerMock> eventHandler;
    handler.HandleLocalHotKey(keyEvent, eventHandler);
    EXPECT_EQ(eventHandler.events_.size(), SINGLE_ITEM);
    if (!eventHandler.events_.empty()) {
        const auto event = eventHandler.events_.front();
        ASSERT_NE(event, nullptr);
        EXPECT_EQ(event->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
        EXPECT_EQ(event->GetKeyCode(), KeyEvent::KEYCODE_CTRL_LEFT);
    }
    auto iter = handler.consumedKeys_.find(KeyEvent::KEYCODE_CTRL_LEFT);
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }
}

/**
 * @tc.name: HandleLocalHotKey_003
 * @tc.desc: Test LocalHotKeyHandler::HandleLocalHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleLocalHotKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetPressed(true);
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->AddPressedKeyItems(key1);

    LocalHotKeyHandler handler;
    handler.MarkProcessed(keyEvent, LocalHotKeyAction::OVER);

    KeyEvent::KeyItem key2 {};
    key2.SetPressed(true);
    key2.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    keyEvent->AddPressedKeyItems(key2);

    KeyEvent::KeyItem key3 {};
    key3.SetPressed(true);
    key3.SetKeyCode(KeyEvent::KEYCODE_G);
    keyEvent->AddPressedKeyItems(key3);

    KeyEvent::KeyItem key4 {};
    key4.SetPressed(true);
    key4.SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->AddPressedKeyItems(key4);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_H);

    InputEventHandlerMock eventHandler;
    handler.HandleLocalHotKey(keyEvent, eventHandler);
    EXPECT_EQ(eventHandler.events_.size(), SINGLE_ITEM);
    if (!eventHandler.events_.empty()) {
        const auto event = eventHandler.events_.front();
        ASSERT_NE(event, nullptr);
        EXPECT_EQ(event->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
        EXPECT_EQ(event->GetKeyCode(), KeyEvent::KEYCODE_SHIFT_LEFT);
    }
    auto iter = handler.consumedKeys_.find(KeyEvent::KEYCODE_SHIFT_LEFT);
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys()
{
    auto fd = ::open(g_dumpName, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        std::vector<std::string> args;
        LocalHotKeyHandler::steward_.Dump(fd, args);
        ::close(fd);
    }
}

void LocalHotKeyHandlerTest::CheckLocalHotKeys(const std::vector<std::string> &expected)
{
    std::ifstream fs(g_dumpName);
    EXPECT_TRUE(fs.is_open());
    if (fs.is_open()) {
        std::string line;
        for (const auto &str : expected) {
            EXPECT_TRUE(std::getline(fs, line));
            EXPECT_EQ(line, str);
        }
        EXPECT_FALSE(std::getline(fs, line));
    }
    fs.close();
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys001()
{
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    DumpLocalHotKeys();
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Test LocalHotKeyHandler::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> expected {
        "local hot keys:",
        "\tKEYCODE:2089, MODIFIERS:{ALT:NONE, SHIFT:DOWN, CTRL:DOWN, META:NONE}, ACTION:COPY",
    };
    DumpLocalHotKeys001();
    CheckLocalHotKeys(expected);
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys002()
{
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    DumpLocalHotKeys();
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Test LocalHotKeyHandler::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, Dump_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> expected {
        "local hot keys:",
        "\tKEYCODE:2089, MODIFIERS:{ALT:NONE, SHIFT:ANY, CTRL:DOWN, META:NONE}, ACTION:COPY",
    };
    DumpLocalHotKeys002();
    CheckLocalHotKeys(expected);
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys003()
{
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    DumpLocalHotKeys();
}

/**
 * @tc.name: Dump_003
 * @tc.desc: Test LocalHotKeyHandler::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, Dump_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> expected {
        "local hot keys:",
        "\tKEYCODE:2017, MODIFIERS:{ALT:NONE, SHIFT:NONE, CTRL:DOWN, META:NONE}, ACTION:COPY",
        "\tKEYCODE:2089, MODIFIERS:{ALT:NONE, SHIFT:DOWN, CTRL:DOWN, META:NONE}, ACTION:COPY",
    };
    DumpLocalHotKeys003();
    CheckLocalHotKeys(expected);
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys004()
{
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::OVER);
    DumpLocalHotKeys();
}

/**
 * @tc.name: Dump_004
 * @tc.desc: Test LocalHotKeyHandler::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, Dump_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> expected {
        "local hot keys:",
        "\tKEYCODE:2017, MODIFIERS:{ALT:NONE, SHIFT:DOWN, CTRL:DOWN, META:NONE}, ACTION:OVER",
        "\tKEYCODE:2017, MODIFIERS:{ALT:NONE, SHIFT:NONE, CTRL:DOWN, META:NONE}, ACTION:COPY",
    };
    DumpLocalHotKeys004();
    CheckLocalHotKeys(expected);
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys005()
{
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    LocalHotKeyHandler::steward_.systemHotKeys_.emplace(KeyEvent::KEYCODE_MEDIA_RECORD);
    DumpLocalHotKeys();
}

/**
 * @tc.name: Dump_005
 * @tc.desc: Test LocalHotKeyHandler::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, Dump_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> expected {
        "local hot keys:",
        "\tKEYCODE:2017, MODIFIERS:{ALT:NONE, SHIFT:DOWN, CTRL:DOWN, META:NONE}, ACTION:COPY",
        "\tKEYCODE:2089, MODIFIERS:{ALT:ANY, SHIFT:ANY, CTRL:ANY, META:ANY}, ACTION:OVER",
    };
    DumpLocalHotKeys005();
    CheckLocalHotKeys(expected);
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys006()
{
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::COPY);
    LocalHotKeyHandler::steward_.systemHotKeys_.emplace(KeyEvent::KEYCODE_MEDIA_RECORD);
    DumpLocalHotKeys();
}

/**
 * @tc.name: Dump_006
 * @tc.desc: Test LocalHotKeyHandler::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, Dump_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> expected {
        "local hot keys:",
        "\tKEYCODE:2089, MODIFIERS:{ALT:NONE, SHIFT:DOWN, CTRL:DOWN, META:NONE}, ACTION:COPY",
        "\tKEYCODE:2089, MODIFIERS:{ALT:ANY, SHIFT:ANY, CTRL:ANY, META:ANY}, ACTION:OVER",
    };
    DumpLocalHotKeys006();
    CheckLocalHotKeys(expected);
}

void LocalHotKeyHandlerTest::DumpLocalHotKeys007()
{
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_MEDIA_RECORD,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT,
        }, LocalHotKeyAction::OVER);
    LocalHotKeyHandler::steward_.systemHotKeys_.emplace(KeyEvent::KEYCODE_MEDIA_RECORD);
    DumpLocalHotKeys();
}

/**
 * @tc.name: Dump_007
 * @tc.desc: Test LocalHotKeyHandler::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, Dump_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> expected {
        "local hot keys:",
        "\tKEYCODE:2089, MODIFIERS:{ALT:ANY, SHIFT:ANY, CTRL:ANY, META:ANY}, ACTION:OVER",
    };
    DumpLocalHotKeys007();
    CheckLocalHotKeys(expected);
}

/**
 * @tc.name: HandleKeyDown_001
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler handler;
    EXPECT_FALSE(handler.HandleKeyDown(nullptr,
        [](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return true;
        }));
}

std::shared_ptr<KeyEvent> LocalHotKeyHandlerTest::BuildKeyEvent0201()
{
    auto keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    KeyEvent::KeyItem key2 {};
    key2.SetKeyCode(KeyEvent::KEYCODE_A);
    key2.SetPressed(true);
    keyEvent->AddKeyItem(key2);
    return keyEvent;
}

/**
 * @tc.name: HandleKeyDown_002
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = BuildKeyEvent0201();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    EXPECT_FALSE(handler.HandleKeyDown(keyEvent,
        [](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return true;
        }));
}

/**
 * @tc.name: HandleKeyDown_003
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyDown_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::INTERCEPT);
    auto keyEvent = BuildKeyEvent0201();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    bool intercepted = false;
    EXPECT_FALSE(handler.HandleKeyDown(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_FALSE(intercepted);
}

/**
 * @tc.name: HandleKeyDown_004
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyDown_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    auto keyEvent = BuildKeyEvent0201();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    bool intercepted = false;
    EXPECT_TRUE(handler.HandleKeyDown(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_TRUE(intercepted);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::COPY);
    }
}

/**
 * @tc.name: HandleKeyDown_005
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyDown_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::OVER);
    auto keyEvent = BuildKeyEvent0201();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    bool intercepted = false;

    EXPECT_TRUE(handler.HandleKeyDown(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_FALSE(intercepted);
    auto iter = handler.consumedKeys_.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, handler.consumedKeys_.cend());
    if (iter != handler.consumedKeys_.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }
}

/**
 * @tc.name: HandleKeyDown_006
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyDown_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::OVER);
    auto keyEvent = BuildKeyEvent0201();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    bool intercepted = false;
    handler.consumedKeys_.emplace(keyEvent->GetKeyCode(), LocalHotKeyAction::COPY);

    EXPECT_TRUE(handler.HandleKeyDown(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_TRUE(intercepted);
}

std::shared_ptr<KeyEvent> LocalHotKeyHandlerTest::BuildKeyEvent0301()
{
    auto keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    KeyEvent::KeyItem key2 {};
    key2.SetKeyCode(KeyEvent::KEYCODE_A);
    key2.SetPressed(false);
    keyEvent->AddKeyItem(key2);
    return keyEvent;
}

/**
 * @tc.name: HandleKeyUp_001
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = BuildKeyEvent0301();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    EXPECT_FALSE(handler.HandleKeyUp(keyEvent,
        [](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return true;
        }));
}

/**
 * @tc.name: HandleKeyUp_002
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = BuildKeyEvent0301();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    handler.consumedKeys_.emplace(KeyEvent::KEYCODE_A, LocalHotKeyAction::COPY);
    bool intercepted = false;
    EXPECT_TRUE(handler.HandleKeyUp(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_TRUE(intercepted);
    EXPECT_EQ(handler.consumedKeys_.find(keyEvent->GetKeyCode()), handler.consumedKeys_.end());
}

/**
 * @tc.name: HandleKeyUp_003
 * @tc.desc: Test LocalHotKeyHandler::HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, HandleKeyUp_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = BuildKeyEvent0301();
    ASSERT_NE(keyEvent, nullptr);
    LocalHotKeyHandler handler;
    handler.consumedKeys_.emplace(KeyEvent::KEYCODE_A, LocalHotKeyAction::OVER);
    bool intercepted = false;
    EXPECT_TRUE(handler.HandleKeyUp(keyEvent,
        [&intercepted](std::shared_ptr<KeyEvent> keyEvent) -> bool {
            intercepted = true;
            return true;
        }));
    EXPECT_FALSE(intercepted);
    EXPECT_EQ(handler.consumedKeys_.find(keyEvent->GetKeyCode()), handler.consumedKeys_.end());
}

/**
 * @tc.name: KeyEvent2LocalHotKey_001
 * @tc.desc: Test LocalHotKeyHandler::KeyEvent2LocalHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, KeyEvent2LocalHotKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler handler;
    auto hotKeyOpt = handler.KeyEvent2LocalHotKey(nullptr);
    EXPECT_FALSE(hotKeyOpt.has_value());
}

/**
 * @tc.name: KeyEvent2LocalHotKey_002
 * @tc.desc: Test LocalHotKeyHandler::KeyEvent2LocalHotKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalHotKeyHandlerTest, KeyEvent2LocalHotKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    KeyEvent::KeyItem key2 {};
    key2.SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    key2.SetPressed(true);
    keyEvent->AddKeyItem(key2);

    KeyEvent::KeyItem key3 {};
    key3.SetKeyCode(KeyEvent::KEYCODE_A);
    key3.SetPressed(true);
    keyEvent->AddKeyItem(key3);

    LocalHotKeyHandler handler;
    auto hotKeyOpt = handler.KeyEvent2LocalHotKey(keyEvent);
    EXPECT_TRUE(hotKeyOpt.has_value());
    if (hotKeyOpt) {
        EXPECT_EQ(hotKeyOpt->keyCode_, KeyEvent::KEYCODE_A);
        EXPECT_EQ(hotKeyOpt->modifiers_,
            (KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_SHIFT));
    }
}
} // namespace MMI
} // namespace OHOS
