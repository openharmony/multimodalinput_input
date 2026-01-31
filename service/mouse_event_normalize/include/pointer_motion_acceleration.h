/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef POINTER_MOTION_ACCELERATION_H
#define POINTER_MOTION_ACCELERATION_H

#include <atomic>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "cJSON.h"
#include "mouse_transform_processor.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class PointerMotionAcceleration final {
private:
    struct Curve {
        std::vector<double> speeds;
        std::vector<double> slopes;
        std::vector<double> diffNums;

        bool IsValid() const;
    };

    using CurveCollection = std::vector<Curve>;

    struct DynamicMouseCurve {
        std::vector<double> speeds;
        std::vector<double> slowGains;
        std::vector<double> fastGains;
        double standardPPI {};

        bool IsValid() const;
    };

    struct DynamicTouchpadCurve {
        std::vector<double> speeds;
        std::vector<double> slopes;
        std::vector<double> stdVins;

        bool IsValid() const;
    };

public:
    static int32_t DynamicAccelerateMouse(const Offset &offset, bool mode, size_t speed,
        uint64_t deltaTime, double displayPPI, double factor, double &absX, double &absY);
    static int32_t DynamicAccelerateTouchpad(const Offset &offset, bool mode, size_t speed,
        double displaySize, double touchpadSize, double touchpadPPI, int32_t frequency, double &absX, double &absY);
    static int32_t AccelerateMouse(
        const Offset &offset, bool mode, size_t speed, DeviceType deviceType, double &absX, double &absY);
    static int32_t AccelerateTouchpad(
        const Offset &offset, bool mode, size_t speed, DeviceType deviceType, double &absX, double &absY);
    static void Dump(int32_t fd, const std::vector<std::string> &args);

private:
    PointerMotionAcceleration() = default;
    ~PointerMotionAcceleration() = default;
    DISALLOW_COPY_AND_MOVE(PointerMotionAcceleration);

    static void LoadAccelerationConfig(std::function<bool(const char*, cJSON*)> load);
    static void LoadConfig(std::function<bool(const char*, cJSON*)> load);
    static bool LoadConfig(const char *cfgPath, std::function<bool(const char*, cJSON*)> load);
    static bool LoadDynamicMouseCurve(const char *cfgPath, cJSON *jsonCfg);
    static bool LoadDynamicMouseStandardPPI(const char *cfgPath, cJSON *jsonCfg, DynamicMouseCurve &curve);
    static bool LoadDynamicTouchpadCurve(const char *cfgPath, cJSON *jsonCfg);
    static bool LoadProperty(cJSON *jsonCfg, const std::string &name, std::vector<double> &property);
    static bool CalcDynamicMouseGain(const DynamicMouseCurve &curve,
        double vin, size_t speed, double displayPPI, double &gain);
    static bool CalcDynamicTouchpadGain(const DynamicTouchpadCurve &curve, double vin, size_t speed,
        double displaySize, double touchpadSize, double touchpadPPI, int32_t frequency, double &gain);
    static std::string GetMouseConfigName(DeviceType devType);
    static std::string GetTouchpadConfigName(DeviceType devType);
    static bool LoadAccelerationCurve(const char *cfgPath, cJSON *jsonCfg, const std::string &name);
    static double CalculateVin(const Offset &offset);
    static bool CalculateSpeedGain(const CurveCollection &curves, double vin, size_t speed, double &gain);
    static const Curve* MatchCurve(const CurveCollection &curves, size_t speed);

    static std::shared_mutex mutex_;
    static std::atomic_bool loading_;
    static std::optional<DynamicMouseCurve> dynamicMouseCurve_;
    static std::optional<DynamicTouchpadCurve> dynamicTouchpadCurve_;
    static std::unordered_map<std::string, CurveCollection> curves_;
    static Offset compensateTouchpad_;
};
} // namespace MMI
} // namespace OHOS
#endif // POINTER_MOTION_ACCELERATION_H
