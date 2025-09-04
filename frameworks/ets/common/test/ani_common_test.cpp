#include "gtest/gtest.h"
#include "ani_common.h"
#include "mmi_log.h"


using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI;

class AniCommonTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
    }
};

/**
 * @tc.name: AniCommonTest_GetApiError_001
 * @tc.desc: AniCommonTest_GetApiError_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AniCommonTest, AniCommonTest_GetApiError_001, TestSize.Level0) {
    TaiheError codeMsg;
    auto code = TaiheErrorCode::COMMON_PERMISSION_CHECK_ERROR;
    bool result = TaiheConverter::GetApiError(code, codeMsg);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: AniCommonTest_GetApiError_002
 * @tc.desc: AniCommonTest_GetApiError_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AniCommonTest, AniCommonTest_GetApiError_002, TestSize.Level0) {
    TaiheError codeMsg;
    auto code = TaiheErrorCode::OTHER_ERROR;
    bool result = TaiheConverter::GetApiError(code, codeMsg);
    EXPECT_FALSE(result);
}