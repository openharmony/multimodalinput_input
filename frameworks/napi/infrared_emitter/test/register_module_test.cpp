/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class RegisterModuleTest : public testing::Test {
    public:
        int64_t frequency_Max;
        int64_t frequency_Min;
};

/**
 * @tc.name: GetInfraredFrequenciesTest
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:AR000GJG6G
 */
HWTEST_F(RegisterModuleTest, GetInfraredFrequenciesTest, TestSize.Level1)
{
    std::vector<InfraredFrequency> requencys;
    int32_t ret = InputManager::GetInstance()->GetInfraredFrequencies(requencys);
    bool testResult = true;
    int32_t size = requencys.size();
    EXPECT_GE(size, 1);
    frequency_Max = requencys[0].max_;
    frequency_Min = requencys[0].min_;
    for (int32_t i = 0; i < size; i++) {
        InfraredFrequency fre = requencys[i];
        if (fre.max_ < fre.min_) {
            testResult = false;
            break;
        }
    }
    EXPECT_EQ(testResult, true);
}

/**
 * @tc.name: EventDumpTest_CheckCount_001
 * @tc.desc: Event dump CheckCount
 * @tc.type: FUNC
 * @tc.require:AR000GJG6G
 */
HWTEST_F(RegisterModuleTest, TransmitInfraredTest, TestSize.Level1)
{
    std::vector<InfraredFrequency> requencys;
    int64_t dist = (frequency_Max - frequency_Min) / 10;
    bool testResult = true;

    for (int i = 0; i < 10; i++) {
        requencys.push_back(dist * i + frequency_Min);
    }
    int32_t ret = InputManager::GetInstance()->TransmitInfrared(frequency_Min, requencys);
    if (0 != ret) {
        testResult = false;
    }
    EXPECT_EQ(testResult, true);
}

HWTEST_F(RegisterModuleTest, HasIrEmitterTest, TestSize.Level1)
{
    bool hasEmmited = false;
    int32_t ret = InputManager::GetInstance()->HasIrEmitter(hasEmmited);
    EXPECT_EQ(hasEmmited, false);
}
} // namespace MMI
} // namespace OHOS