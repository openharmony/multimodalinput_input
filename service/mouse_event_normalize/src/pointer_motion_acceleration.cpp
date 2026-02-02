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

#include "pointer_motion_acceleration.h"

#include <cmath>
#include <fstream>

#include "config_policy_utils.h"
#include "define_multimodal.h"
#include "ffrt.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerMotionAcceleration"

namespace OHOS {
namespace MMI {
namespace {
constexpr double COEFFICIENT_DOUBLE { 2.0 };
constexpr double TOUCHPAD_STANDARD_SIZE { 140.0 };
constexpr double DISPLAY_STANDARD_SIZE { 337.8 };
constexpr double DYNAMIC_MOUSE_VIN_THRESHOLD { 13.5 };
constexpr double MIN_DISPLAY_PPI { 1.0 };
constexpr double DEFAULT_PRECISION { 0.0001 };
constexpr size_t FIRST_ITEM { 0 };
constexpr size_t SECOND_ITEM { 1 };
constexpr size_t THIRD_ITEM { 2 };
constexpr size_t FORTH_ITEM { 3 };
constexpr size_t DYNAMIC_MOUSE_N_SPEEDS { 20 };
constexpr size_t DYNAMIC_MOUSE_N_GAIN_PARAMS { 4 };
constexpr size_t DYNAMIC_TOUCHPAD_N_SPEEDS { 11 };
constexpr size_t DYNAMIC_TOUCHPAD_N_CURVE_SLOPES { 4 };
constexpr std::uintmax_t MAX_SIZE_OF_INPUT_PRODUCT_CONFIG { 524288 }; // 512KB
} // namespace

std::shared_mutex PointerMotionAcceleration::mutex_ {};
std::atomic_bool PointerMotionAcceleration::loading_ { false };
std::optional<PointerMotionAcceleration::DynamicMouseCurve> PointerMotionAcceleration::dynamicMouseCurve_ {};
std::optional<PointerMotionAcceleration::DynamicTouchpadCurve> PointerMotionAcceleration::dynamicTouchpadCurve_ {};
std::unordered_map<std::string, PointerMotionAcceleration::CurveCollection> PointerMotionAcceleration::curves_ {};
Offset PointerMotionAcceleration::compensateTouchpad_ {};

bool PointerMotionAcceleration::Curve::IsValid() const
{
    return (!speeds.empty() &&
            (slopes.size() >= speeds.size()) &&
            (diffNums.size() >= speeds.size()));
}

bool PointerMotionAcceleration::DynamicMouseCurve::IsValid() const
{
    return ((speeds.size() == DYNAMIC_MOUSE_N_SPEEDS) &&
            (slowGains.size() == DYNAMIC_MOUSE_N_GAIN_PARAMS) &&
            (fastGains.size() == DYNAMIC_MOUSE_N_GAIN_PARAMS));
}

bool PointerMotionAcceleration::DynamicTouchpadCurve::IsValid() const
{
    return ((speeds.size() == DYNAMIC_TOUCHPAD_N_SPEEDS) &&
            (slopes.size() == DYNAMIC_TOUCHPAD_N_CURVE_SLOPES) &&
            (stdVins.size() == DYNAMIC_TOUCHPAD_N_CURVE_SLOPES));
}

int32_t PointerMotionAcceleration::DynamicAccelerateMouse(const Offset &offset, bool mode, size_t speed,
    uint64_t deltaTime, double displayPPI, double factor, double &absX, double &absY)
{
    MMI_HILOGD("Accelerate mouse motion dynamically, mode:%{public}d, speed:%{public}zu, "
        "deltaTime:%{public}" PRIu64 ", displayPPI:%{public}f, factor:%{public}f",
        mode, speed, deltaTime, displayPPI, factor);
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!dynamicMouseCurve_) {
        ffrt::submit([]() {
            PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadDynamicMouseCurve);
        });
    }
    const auto vin = std::hypot(offset.dx, offset.dy);
    double gain { 1.0 };

    if (dynamicMouseCurve_ &&
        !CalcDynamicMouseGain(*dynamicMouseCurve_, vin, speed, displayPPI, gain)) {
        MMI_HILOGW("CalcDynamicMouseGain fail, vin:%{public}f, speed:%{public}zu, displayPPI:%{public}f",
            vin, speed, displayPPI);
    }
    if (!mode) {
        absX += offset.dx * factor * gain;
        absY += offset.dy * factor * gain;
    }
    MMI_HILOGD("Accelerated mouse motion (absX:%{private}f, absY:%{private}f)", absX, absY);
    return RET_OK;
}

int32_t PointerMotionAcceleration::DynamicAccelerateTouchpad(const Offset &offset, bool mode, size_t speed,
    double displaySize, double touchpadSize, double touchpadPPI, int32_t frequency, double &absX, double &absY)
{
    MMI_HILOGD("Accelerate touchpad motion, mode:%{public}d, speed:%{public}zu, "
        "displaySize:%{public}f, touchpadSize:%{public}f, touchpadPPI:%{public}f, frequency:%{public}d",
        mode, speed, displaySize, touchpadSize, touchpadPPI, frequency);
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!dynamicTouchpadCurve_) {
        ffrt::submit([]() {
            PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadDynamicTouchpadCurve);
        });
    }
    const auto vin = std::hypot(offset.dx, offset.dy);
    double gain { 1.0 };

    if (dynamicTouchpadCurve_ &&
        !CalcDynamicTouchpadGain(*dynamicTouchpadCurve_, vin, speed,
                                 displaySize, touchpadSize, touchpadPPI, frequency, gain)) {
        MMI_HILOGW("CalcDynamicTouchpadGain(vin:%{public}f, speed:%{public}zu, displaySize:%{public}f, "
            "touchpadSize:%{public}f, touchpadPPI:%{public}f, frequency:%{public}d) fail",
            vin, speed, displaySize, touchpadSize, touchpadPPI, frequency);
    }
    if (!mode) {
        double dx {};
        double dy {};
        compensateTouchpad_.dx = std::modf(offset.dx * gain + compensateTouchpad_.dx, &dx);
        compensateTouchpad_.dy = std::modf(offset.dy * gain + compensateTouchpad_.dy, &dy);
        absX += dx;
        absY += dy;
    }
    MMI_HILOGD("Accelerated touchpad motion (absX:%{private}f, absY:%{private}f)", absX, absY);
    return RET_OK;
}

int32_t PointerMotionAcceleration::AccelerateMouse(
    const Offset &offset, bool mode, size_t speed, DeviceType deviceType, double &absX, double &absY)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto name = PointerMotionAcceleration::GetMouseConfigName(deviceType);
    auto iter = curves_.find(name);
    if (iter == curves_.cend()) {
        ffrt::submit([name]() {
            PointerMotionAcceleration::LoadAccelerationConfig([name](const char *cfgPath, cJSON *jsonCfg) {
                return PointerMotionAcceleration::LoadAccelerationCurve(cfgPath, jsonCfg, name);
            });
        });
    }
    const double vin = PointerMotionAcceleration::CalculateVin(offset);
    double gain { 1.0 };

    if ((iter != curves_.cend()) &&
        !CalculateSpeedGain(iter->second, vin, speed, gain)) {
        MMI_HILOGW("CalculateSpeedGain fail");
    }
    if (!mode) {
        absX += offset.dx * gain;
        absY += offset.dy * gain;
    }
    MMI_HILOGD("Accelerated mouse motion (abs_x: %{private}f, abs_y: %{private}f)", absX, absY);
    return RET_OK;
}

int32_t PointerMotionAcceleration::AccelerateTouchpad(
    const Offset &offset, bool mode, size_t speed, DeviceType deviceType, double &absX, double &absY)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto name = PointerMotionAcceleration::GetTouchpadConfigName(deviceType);
    auto iter = curves_.find(name);
    if (iter == curves_.cend()) {
        ffrt::submit([name]() {
            PointerMotionAcceleration::LoadAccelerationConfig([name](const char *cfgPath, cJSON *jsonCfg) {
                return PointerMotionAcceleration::LoadAccelerationCurve(cfgPath, jsonCfg, name);
            });
        });
    }
    const double vin = CalculateVin(offset);
    double gain { 1.0 };

    if ((iter != curves_.cend()) &&
        !CalculateSpeedGain(iter->second, vin, speed, gain)) {
        MMI_HILOGW("CalculateSpeedGain fail");
    }
    if (!mode) {
        double dx {};
        double dy {};
        compensateTouchpad_.dx = std::modf(offset.dx * gain + compensateTouchpad_.dx, &dx);
        compensateTouchpad_.dy = std::modf(offset.dy * gain + compensateTouchpad_.dy, &dy);
        absX += dx;
        absY += dy;
    }
    MMI_HILOGD("Accelerated touchpad motion (abs_x: %{private}f, abs_y: %{private}f)", absX, absY);
    return RET_OK;
}

void PointerMotionAcceleration::Dump(int32_t fd, const std::vector<std::string> &args)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    mprintf(fd, "Pointer acceleration curves:");
    if (curves_.empty() && !dynamicMouseCurve_ && !dynamicTouchpadCurve_) {
        mprintf(fd, "\tThere is no acceleration curve.");
        return;
    }
    for (const auto &[name, curves] : curves_) {
        mprintf(fd, "\tPointer acceleration curves (%s) {", name.c_str());
        size_t index = 0;

        for (const auto &curve : curves) {
            mprintf(fd, "\t\tPointer acceleration curve (%s)[%zu] {", name.c_str(), index);
            mprintf(fd, "\t\t\tspeeds: [%s]", DumpVec(curve.speeds).c_str());
            mprintf(fd, "\t\t\tslopes: [%s]", DumpVec(curve.slopes).c_str());
            mprintf(fd, "\t\t\tdiff_nums: [%s]", DumpVec(curve.diffNums).c_str());
            mprintf(fd, "\t\t}");
            ++index;
        }
        mprintf(fd, "\t}");
    }
    if (dynamicMouseCurve_) {
        mprintf(fd, "\tPointer acceleration curves (MouseDynamic) {");
        mprintf(fd, "\t\tDynamic mouse acceleration curve {");
        mprintf(fd, "\t\t\tspeeds: [%s]", DumpVec(dynamicMouseCurve_->speeds).c_str());
        mprintf(fd, "\t\t\tslow_gains: [%s]", DumpVec(dynamicMouseCurve_->slowGains).c_str());
        mprintf(fd, "\t\t\tfast_gains: [%s]", DumpVec(dynamicMouseCurve_->fastGains).c_str());
        mprintf(fd, "\t\t\tstandard_ppi: %f", dynamicMouseCurve_->standardPPI);
        mprintf(fd, "\t\t}");
        mprintf(fd, "\t}");
    }
    if (dynamicTouchpadCurve_) {
        mprintf(fd, "\tPointer acceleration curves (TouchpadDynamic) {");
        mprintf(fd, "\t\tDynamic touchpad acceleration curve {");
        mprintf(fd, "\t\t\tspeeds: [%s]", DumpVec(dynamicTouchpadCurve_->speeds).c_str());
        mprintf(fd, "\t\t\tslopes: [%s]", DumpVec(dynamicTouchpadCurve_->slopes).c_str());
        mprintf(fd, "\t\t\tstandard_vins: [%s]", DumpVec(dynamicTouchpadCurve_->stdVins).c_str());
        mprintf(fd, "\t\t}");
        mprintf(fd, "\t}");
    }
}

void PointerMotionAcceleration::LoadAccelerationConfig(std::function<bool(const char*, cJSON*)> load)
{
    if (loading_.load()) {
        return;
    }
    loading_.store(true);
    LoadConfig(load);
    loading_.store(false);
}

void PointerMotionAcceleration::LoadConfig(std::function<bool(const char*, cJSON *)> load)
{
    char cfgName[] { "etc/multimodalinput/pointer_motion_acceleration_config.json" };
    auto cfgNames = std::unique_ptr<CfgFiles, std::function<void(CfgFiles*)>>(
        ::GetCfgFiles(cfgName),
        [](CfgFiles *names) {
            if (names != nullptr) {
                ::FreeCfgFiles(names);
            }
        });
    if (cfgNames == nullptr) {
        MMI_HILOGW("Can not find pointer-motion-acceleration config");
        return;
    }
    for (int32_t index = MAX_CFG_POLICY_DIRS_CNT - 1; index >= 0; --index) {
        if (cfgNames->paths[index] == nullptr) {
            continue;
        }
        MMI_HILOGD("Try loading pointer-motion-ccceleration from '%{private}s'", cfgNames->paths[index]);
        if (LoadConfig(cfgNames->paths[index], load)) {
            MMI_HILOGI("Load pointer-motion-ccceleration from '%{private}s'", cfgNames->paths[index]);
            return;
        }
    }
}

bool PointerMotionAcceleration::LoadConfig(const char *cfgPath, std::function<bool(const char*, cJSON*)> load)
{
    std::error_code ec {};
    auto realPath = std::filesystem::canonical(cfgPath, ec);
    if (ec || !std::filesystem::exists(realPath, ec)) {
        MMI_HILOGE("'%{private}s' is not real", cfgPath);
        return false;
    }
    auto fsize = std::filesystem::file_size(realPath, ec);
    if (ec || (fsize > MAX_SIZE_OF_INPUT_PRODUCT_CONFIG)) {
        MMI_HILOGE("Unexpected size of PointerMotionAccelerationConfig");
        return false;
    }
    std::ifstream ifs(realPath);
    if (!ifs.is_open()) {
        MMI_HILOGE("Can not open config");
        return false;
    }
    std::string sConfig { std::istream_iterator<char>(ifs), std::istream_iterator<char>() };
    auto jsonCfg = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_Parse(sConfig.c_str()),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    if (jsonCfg == nullptr) {
        MMI_HILOGE("'%{private}s' is not json", cfgPath);
        return false;
    }
    return load(cfgPath, jsonCfg.get());
}

bool PointerMotionAcceleration::LoadDynamicMouseCurve(const char *cfgPath, cJSON *jsonCfg)
{
    const char name[] { "MouseDynamic" };
    auto jsonMouseDynamic = cJSON_GetObjectItemCaseSensitive(jsonCfg, name);
    if (jsonMouseDynamic == nullptr) {
        MMI_HILOGE("Invalid config(%{private}s): no '%{public}s'", cfgPath, name);
        return false;
    }
    if (!cJSON_IsObject(jsonMouseDynamic)) {
        MMI_HILOGE("Invalid config(%{private}s): '%{public}s' is not object", cfgPath, name);
        return false;
    }
    DynamicMouseCurve curve {};
    bool valid = (
        LoadProperty(jsonMouseDynamic, std::string("speeds"), curve.speeds) &&
        LoadProperty(jsonMouseDynamic, std::string("slow_gains"), curve.slowGains) &&
        LoadProperty(jsonMouseDynamic, std::string("fast_gains"), curve.fastGains) &&
        LoadDynamicMouseStandardPPI(cfgPath, jsonMouseDynamic, curve) &&
        curve.IsValid()
    );
    if (!valid) {
        MMI_HILOGE("Invalid config(%{private}s): '%{public}s' is invalid", cfgPath, name);
        return false;
    }
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        dynamicMouseCurve_ = std::move(curve);
    }
    return true;
}

bool PointerMotionAcceleration::LoadDynamicMouseStandardPPI(
    const char *cfgPath, cJSON *jsonCfg, DynamicMouseCurve &curve)
{
    const char name[] { "standard_ppi" };
    auto jsonStdPPI = cJSON_GetObjectItemCaseSensitive(jsonCfg, name);
    if (jsonStdPPI == nullptr) {
        MMI_HILOGE("Invalid config(%{private}s): no '%{public}s'", cfgPath, name);
        return false;
    }
    if (!cJSON_IsNumber(jsonStdPPI)) {
        MMI_HILOGE("Invalid config(%{private}s): '%{public}s' is not number", cfgPath, name);
        return false;
    }
    curve.standardPPI = cJSON_GetNumberValue(jsonStdPPI);
    return true;
}

bool PointerMotionAcceleration::LoadDynamicTouchpadCurve(const char *cfgPath, cJSON *jsonCfg)
{
    const char name[] { "TouchpadDynamic" };
    auto jsonTouchpadDynamic = cJSON_GetObjectItemCaseSensitive(jsonCfg, name);
    if (jsonTouchpadDynamic == nullptr) {
        MMI_HILOGE("Invalid config(%{private}s): no '%{public}s'", cfgPath, name);
        return false;
    }
    if (!cJSON_IsObject(jsonTouchpadDynamic)) {
        MMI_HILOGE("Invalid config(%{private}s): '%{public}s' is not object", cfgPath, name);
        return false;
    }
    DynamicTouchpadCurve curve {};
    bool valid = (
        LoadProperty(jsonTouchpadDynamic, std::string("speeds"), curve.speeds) &&
        LoadProperty(jsonTouchpadDynamic, std::string("slopes"), curve.slopes) &&
        LoadProperty(jsonTouchpadDynamic, std::string("standard_vins"), curve.stdVins) &&
        curve.IsValid()
    );
    if (!valid) {
        MMI_HILOGE("Invalid config(%{private}s): '%{public}s' is invalid", cfgPath, name);
        return false;
    }
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        dynamicTouchpadCurve_ = std::move(curve);
    }
    return true;
}

bool PointerMotionAcceleration::LoadProperty(cJSON *jsonCfg, const std::string &name, std::vector<double> &property)
{
    auto jsonProperty = cJSON_GetObjectItemCaseSensitive(jsonCfg, name.c_str());
    if (jsonProperty == nullptr) {
        MMI_HILOGE("Invalid config: no '%{public}s'", name.c_str());
        return false;
    }
    if (!cJSON_IsArray(jsonProperty)) {
        MMI_HILOGE("Invalid config: '%{public}s' is not array", name.c_str());
        return false;
    }
    int32_t nSpeeds = cJSON_GetArraySize(jsonProperty);
    for (int32_t index = 0; index < nSpeeds; ++index) {
        auto jsonItem = cJSON_GetArrayItem(jsonProperty, index);
        if (jsonItem == nullptr) {
            MMI_HILOGE("Invalid config: %{public}s[%{public}d] is null", name.c_str(), index);
            return false;
        }
        if (!cJSON_IsNumber(jsonItem)) {
            MMI_HILOGE("Invalid config: %{public}s[%{public}d] is not number", name.c_str(), index);
            return false;
        }
        property.push_back(cJSON_GetNumberValue(jsonItem));
    }
    return true;
}

bool PointerMotionAcceleration::CalcDynamicMouseGain(const DynamicMouseCurve &curve,
    double vin, size_t speed, double displayPPI, double &gain)
{
    if (displayPPI < MIN_DISPLAY_PPI) {
        MMI_HILOGE("The displayPPI(%{public}f) is out of range", displayPPI);
        return false;
    }
    if ((speed <= 0) || (speed > curve.speeds.size())) {
        MMI_HILOGE("The speed(%{public}zu) is out of range", speed);
        return false;
    }
    if ((curve.slowGains.size() < DYNAMIC_MOUSE_N_GAIN_PARAMS) ||
        (curve.fastGains.size() < DYNAMIC_MOUSE_N_GAIN_PARAMS)) {
        MMI_HILOGE("DynamicMouseCurve is invalid");
        return false;
    }
    if (MMI_EQ(curve.standardPPI, 0.0, DEFAULT_PRECISION)) {
        MMI_HILOGE("Standard PPI is 0");
        return false;
    }
    const double ppiRatio = displayPPI / curve.standardPPI;
    const double speedRadio = curve.speeds[speed - 1];
    double tGain = 0.0;

    if (vin < DYNAMIC_MOUSE_VIN_THRESHOLD) {
        tGain = (curve.slowGains[FIRST_ITEM] *
                 std::log(curve.slowGains[SECOND_ITEM] * vin + curve.slowGains[THIRD_ITEM]) +
                 curve.slowGains[FORTH_ITEM]);
    } else {
        tGain = (curve.fastGains[FIRST_ITEM] *
                 std::log(curve.fastGains[SECOND_ITEM] * std::log(vin) - curve.fastGains[THIRD_ITEM]) +
                 curve.fastGains[FORTH_ITEM]);
    }
    gain = tGain * speedRadio * ppiRatio;
    MMI_HILOGD("gain is set to %{public}f", gain);
    return true;
}

bool PointerMotionAcceleration::CalcDynamicTouchpadGain(const DynamicTouchpadCurve &curve, double vin, size_t speed,
    double displaySize, double touchpadSize, double touchpadPPI, int32_t frequency, double &gain)
{
    MMI_HILOGD("CalcDynamicTouchpadGain, vin:%{public}f,speed:%{public}zu,touchpadSize:%{public}f,"
        "displaySize:%{public}f,touchpadPPI:%{public}f,frequency:%{public}d",
        vin, speed, touchpadSize, displaySize, touchpadPPI, frequency);
    if ((speed <= 0) || (speed > curve.speeds.size())) {
        MMI_HILOGE("Speed(%{public}zu) is out of range", speed);
        return false;
    }
    if ((curve.slopes.size() < DYNAMIC_TOUCHPAD_N_CURVE_SLOPES) ||
        (curve.stdVins.size() < DYNAMIC_TOUCHPAD_N_CURVE_SLOPES)) {
        MMI_HILOGE("DynamicTouchpadCurve is invalid");
        return false;
    }
    if ((frequency == 0) || MMI_EQ(touchpadSize, 0.0, DEFAULT_PRECISION) || MMI_EQ(vin, 0.0, DEFAULT_PRECISION)) {
        MMI_HILOGE("Param is invalid");
        return false;
    }
    auto speedRadio = curve.speeds[speed - 1];
    std::vector<double> slopes;
    std::vector<double> diffNums;
    std::vector<double> vins;

    for (size_t index = 0; index < DYNAMIC_TOUCHPAD_N_CURVE_SLOPES; ++index) {
        vins.push_back(curve.stdVins[index] * touchpadPPI / frequency);
        slopes.push_back(curve.slopes[index] * (displaySize / touchpadSize) *
            (TOUCHPAD_STANDARD_SIZE / DISPLAY_STANDARD_SIZE));
        if (index == FIRST_ITEM) {
            diffNums.push_back(0.0);
            continue;
        }
        diffNums.push_back((slopes[index - 1] - slopes[index]) * vins[index - 1] + diffNums[index - 1]);
    }
    const auto absVin = std::fabs(vin);
    for (size_t index = 0; index < DYNAMIC_TOUCHPAD_N_CURVE_SLOPES; ++index) {
        if (absVin <= vins[index]) {
            gain = (slopes[index] * vin + diffNums[index]) * speedRadio / vin;
            MMI_HILOGD("gain is set to %{public}f", gain);
            return true;
        }
    }
    gain = (slopes[FORTH_ITEM] * vin + diffNums[FORTH_ITEM]) * speedRadio / vin;
    MMI_HILOGD("gain is set to %{public}f", gain);
    return true;
}

std::string PointerMotionAcceleration::GetMouseConfigName(DeviceType devType)
{
    static std::unordered_map<DeviceType, std::string> names {
        { DeviceType::DEVICE_PC, std::string("PCMouse") },
        { DeviceType::DEVICE_SOFT_PC_PRO, std::string("SoftPcProMouse") },
        { DeviceType::DEVICE_HARD_PC_PRO, std::string("HardPcProMouse") },
    };
    if (auto iter = names.find(devType); iter != names.cend()) {
        return iter->second;
    }
    return std::string("PCMouse");
}

std::string PointerMotionAcceleration::GetTouchpadConfigName(DeviceType devType)
{
    static std::unordered_map<DeviceType, std::string> names {
        { DeviceType::DEVICE_PC, std::string("PCTouchpad") },
        { DeviceType::DEVICE_SOFT_PC_PRO, std::string("SoftPcProTouchpad") },
        { DeviceType::DEVICE_HARD_PC_PRO, std::string("HardPcProTouchpad") },
        { DeviceType::DEVICE_TABLET, std::string("TabletTouchpad") },
        { DeviceType::DEVICE_FOLD_PC, std::string("FoldPcTouchpad") },
        { DeviceType::DEVICE_FOLD_PC_VIRT, std::string("FoldPcVirtTouchpad") },
    };
    if (auto iter = names.find(devType); iter != names.cend()) {
        return iter->second;
    }
    return std::string("PCTouchpad");
}

bool PointerMotionAcceleration::LoadAccelerationCurve(const char *cfgPath, cJSON *jsonCfg, const std::string &name)
{
    auto jsonCurves = cJSON_GetObjectItemCaseSensitive(jsonCfg, name.c_str());
    if (jsonCurves == nullptr) {
        MMI_HILOGE("Invalid config(%{private}s): no '%{public}s'", cfgPath, name.c_str());
        return false;
    }
    if (!cJSON_IsArray(jsonCurves)) {
        MMI_HILOGE("Invalid config(%{private}s): '%{public}s' is not array", cfgPath, name.c_str());
        return false;
    }
    CurveCollection curves;

    for (int32_t index = 0, nCurves = cJSON_GetArraySize(jsonCurves); index < nCurves; ++index) {
        auto jsonCurve = cJSON_GetArrayItem(jsonCurves, index);
        if (jsonCurve == nullptr) {
            MMI_HILOGE("Invalid config(%{private}s): %{public}s[%{public}d] is null", cfgPath, name.c_str(), index);
            return false;
        }
        if (!cJSON_IsObject(jsonCurve)) {
            MMI_HILOGE("Invalid config(%{private}s): %{public}s[%{public}d] is not object",
                cfgPath, name.c_str(), index);
            return false;
        }
        Curve curve {};
        bool valid = (
            LoadProperty(jsonCurve, std::string("speeds"), curve.speeds) &&
            LoadProperty(jsonCurve, std::string("slopes"), curve.slopes) &&
            LoadProperty(jsonCurve, std::string("diff_nums"), curve.diffNums) &&
            curve.IsValid()
        );
        if (!valid) {
            MMI_HILOGE("Invalid config(%{private}s): %{public}s[%{public}d] is invalid", cfgPath, name.c_str(), index);
            return false;
        }
        curves.push_back(std::move(curve));
    }
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        curves_.emplace(name, std::move(curves));
    }
    return true;
}

double PointerMotionAcceleration::CalculateVin(const Offset &offset)
{
    return (std::fmax(std::fabs(offset.dx), std::fabs(offset.dy)) +
            std::fmin(std::fabs(offset.dx), std::fabs(offset.dy)) / COEFFICIENT_DOUBLE);
}

bool PointerMotionAcceleration::CalculateSpeedGain(
    const CurveCollection &curves, double vin, size_t speed, double &gain)
{
    const auto curve = MatchCurve(curves, speed);
    if (curve == nullptr) {
        MMI_HILOGE("No match curve");
        return false;
    }
    if (curve->speeds.empty() ||
        (curve->slopes.size() < curve->speeds.size()) ||
        (curve->diffNums.size() < curve->speeds.size())) {
        MMI_HILOGE("Invalid acceleration curve");
        return false;
    }
    if (MMI_EQ(vin, 0.0, DEFAULT_PRECISION)) {
        MMI_HILOGE("Param is invalid");
        return false;
    }
    const auto absVin = std::fabs(vin);
    const auto nSegments = curve->speeds.size();

    for (size_t index = 0; index < nSegments; ++index) {
        if (absVin <= curve->speeds[index]) {
            gain = (curve->slopes[index] * vin + curve->diffNums[index]) / vin;
            MMI_HILOGD("slope is set to %{public}f, gain is %{public}f", curve->slopes[index], gain);
            return true;
        }
    }
    gain = (curve->slopes[nSegments - 1] * vin + curve->diffNums[nSegments - 1]) / vin;
    MMI_HILOGD("slope is set to %{public}f, gain is %{public}f", curve->slopes[nSegments - 1], gain);
    return true;
}

const PointerMotionAcceleration::Curve* PointerMotionAcceleration::MatchCurve(
    const CurveCollection &curves, size_t speed)
{
    if (curves.empty()) {
        MMI_HILOGE("No acceleration curve");
        return nullptr;
    }
    if ((speed > 0) && (speed <= curves.size())) {
        return &curves[speed - 1];
    } else {
        return &curves[curves.size() - 1];
    }
}
} // namespace MMI
} // namespace OHOS
