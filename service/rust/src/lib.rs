/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

//!
use hilog_rust::{error, hilog, debug, HiLogLabel, LogType};
use std::ffi::{c_char, CString};
use std::sync::Once;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002800,
    tag: "MMIRustLib",
};

static DOUBLE_ZERO: f64 = 1e-6;
static RET_OK: i32 = 0;
static RET_ERR: i32 = -1;
static mut COMPENSATE_VALUEX: f64 = 0.0;
static mut COMPENSATE_VALUEY: f64 = 0.0;
static MOUSE_DPI: f64 = 800.0;
static MS_2_US: f64 = 1000.0;

struct CurveItem {
    pub speeds: Vec<f64>,
    pub slopes: Vec<f64>,
    pub diff_nums: Vec<f64>,
}

struct PCMouseAccelerateCurves {
    data: Vec<CurveItem>,
}
struct SoftPcProMouseAccelerateCurves {
    data: Vec<CurveItem>,
}
struct HardPcProMouseAccelerateCurves {
    data: Vec<CurveItem>,
}
struct PCTouchpadAccelerateCurves {
    data: Vec<CurveItem>,
}
struct SoftPcProTouchpadAccelerateCurves {
    data: Vec<CurveItem>,
}
struct HardPcProTouchpadAccelerateCurves {
    data: Vec<CurveItem>,
}
struct TabletTouchpadAccelerateCurves {
    data: Vec<CurveItem>,
}
struct FoldPcTouchpadAccelerateCurves{
    data: Vec<CurveItem>,
}
struct AxisAccelerateCurvesTouchpad {
    data: Vec<CurveItem>,
}
impl PCMouseAccelerateCurves {
    fn pc_mouse_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl SoftPcProMouseAccelerateCurves {
    fn soft_pc_pro_mouse_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl HardPcProMouseAccelerateCurves {
    fn hard_pc_pro_mouse_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl PCTouchpadAccelerateCurves {
    fn pc_touchpad_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl SoftPcProTouchpadAccelerateCurves {
    fn soft_pc_pro_touchpad_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl HardPcProTouchpadAccelerateCurves {
    fn hard_pc_pro_touchpad_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl TabletTouchpadAccelerateCurves {
    fn tablet_touchpad_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl FoldPcTouchpadAccelerateCurves {
    fn fold_pc_touchpad_get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed- 1]
    }
}
impl AxisAccelerateCurvesTouchpad {
    fn get_axis_curve_by_speed_touchpad(&self, device_type: usize) -> &CurveItem {
        &self.data[device_type - 1]
    }
}

impl PCMouseAccelerateCurves {
    fn get_instance() -> &'static PCMouseAccelerateCurves {
        static mut GLOBAL_CURVES: Option<PCMouseAccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(PCMouseAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.16, 0.30, 0.56],
                        diff_nums: vec![0.0, -1.12, -9.44],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.32, 0.60, 1.12],
                        diff_nums: vec![0.0, -2.24, -18.88],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.64, 1.2, 2.24],
                        diff_nums: vec![0.0, -4.48, -37.76],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.80, 1.50, 2.80],
                        diff_nums: vec![0.0, -5.6, -47.2],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.92, 2.40, 4.48],
                        diff_nums: vec![0.0, -11.84, -78.4],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.04, 3.30, 6.16],
                        diff_nums: vec![0.0, -18.08, -109.60],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.10, 3.75, 7.00],
                        diff_nums: vec![0.0, -21.2, -125.20],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.16, 4.20, 7.84],
                        diff_nums: vec![0.0, -24.32, -140.8],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.22, 4.65, 8.68],
                        diff_nums: vec![0.0, -27.44, -156.40],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.28, 5.1, 9.52],
                        diff_nums: vec![0.0, -30.56, -172.00],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.34, 5.55, 10.36],
                        diff_nums: vec![0.0, -33.68, -187.6],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl SoftPcProMouseAccelerateCurves {
    fn get_instance() -> &'static SoftPcProMouseAccelerateCurves {
        static mut GLOBAL_CURVES: Option<SoftPcProMouseAccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(SoftPcProMouseAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![0.10, 0.13, 0.27, 0.44],
                        diff_nums: vec![0.00, -0.11, -1.53, -4.26],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![0.19, 0.25, 0.54, 0.87],
                        diff_nums: vec![0.00, -0.21, -3.06, -8.52],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![0.29, 0.38, 0.81, 1.31],
                        diff_nums: vec![0.00, -0.32, -4.60, -12.78],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![0.39, 0.50, 1.08, 1.74],
                        diff_nums: vec![0.00, -0.42, -6.13, -17.04],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![0.58, 0.75, 1.63, 2.62],
                        diff_nums: vec![0.00, -0.63, -9.19, -25.56],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![0.78, 1.00, 2.17, 3.49],
                        diff_nums: vec![0.00, -0.84, -12.25, -34.09],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![0.97, 1.25, 2.71, 4.36],
                        diff_nums: vec![0.00, -1.05, -15.32, -42.61],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![1.16, 1.50, 3.25, 5.23],
                        diff_nums: vec![0.00, -1.26, -18.38, -51.13],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![1.36, 1.75, 3.79, 6.10],
                        diff_nums: vec![0.00, -1.47, -21.44, -59.65],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![1.65, 2.13, 4.61, 7.41],
                        diff_nums: vec![0.00, -1.79, -26.04, -72.43],
                    },
                    CurveItem {
                        speeds: vec![3.76, 9.77, 16.54, 128.0],
                        slopes: vec![1.94, 2.50, 5.42, 8.72],
                        diff_nums: vec![0.00, -2.11, -30.63, -85.22],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl HardPcProMouseAccelerateCurves {
    fn get_instance() -> &'static HardPcProMouseAccelerateCurves {
        static mut GLOBAL_CURVES: Option<HardPcProMouseAccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(HardPcProMouseAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.20, 0.38, 0.71],
                        diff_nums: vec![0.0, -1.42, -11.98],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.41, 0.76, 1.42],
                        diff_nums: vec![0.0, -2.84, -23.97],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![0.81, 1.52, 2.84],
                        diff_nums: vec![0.0, -5.69, -47.94],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.02, 1.90, 3.55],
                        diff_nums: vec![0.0, -7.11, -59.92],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.17, 3.05, 5.69],
                        diff_nums: vec![0.0, -15.03, -99.53],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.32, 4.19, 7.82],
                        diff_nums: vec![0.0, -22.95, -139.14],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.40, 4.76, 8.89],
                        diff_nums: vec![0.0, -26.91, -158.95],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.47, 5.33, 9.95],
                        diff_nums: vec![0.0, -30.88, -178.75],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.55, 5.90, 11.02],
                        diff_nums: vec![0.0, -34.84, -198.56],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.63, 6.47, 12.09],
                        diff_nums: vec![0.0, -38.80, -218.36],
                    },
                    CurveItem {
                        speeds: vec![8.0, 32.0, 128.0],
                        slopes: vec![1.70, 7.05, 13.15],
                        diff_nums: vec![0.0, -42.76, -238.17],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl PCTouchpadAccelerateCurves {
    fn get_instance() -> &'static PCTouchpadAccelerateCurves {
        static mut GLOBAL_CURVES: Option<PCTouchpadAccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(PCTouchpadAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.14, 0.25, 0.53, 1.03],
                        diff_nums: vec![0.0, -0.14, -3.74, -13.19]
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.19, 0.33, 0.71, 1.37],
                        diff_nums: vec![0.0, -0.18, -4.98, -17.58],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.24, 0.41, 0.88, 1.71],
                        diff_nums: vec![0.0, -0.21, -5.91, -20.88],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.28, 0.49, 1.06, 2.05],
                        diff_nums: vec![0.0, -0.27, -7.47, -26.37],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.38, 0.66, 1.41, 2.73],
                        diff_nums: vec![0.0, -0.36, -9.96, -35.16],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.47, 0.82, 1.77, 3.42],
                        diff_nums: vec![0.0, -0.45, -12.45, -43.95],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.57, 0.99, 2.12, 4.10],
                        diff_nums: vec![0.0, -0.54, -14.94, -52.74],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.71, 1.24, 2.65, 5.13],
                        diff_nums: vec![0.0, -0.68, -18.68, -65.93],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.90, 1.57, 3.36, 6.49],
                        diff_nums: vec![0.0, -0.86, -23.66, -83.51],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![1.08, 1.90, 4.07, 7.86],
                        diff_nums: vec![0.0, -1.04, -28.64, -101.09],
                    },
                    CurveItem {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![1.27, 2.23, 4.77, 9.23],
                        diff_nums: vec![0.0, -1.22, -33.62, -118.67],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl SoftPcProTouchpadAccelerateCurves {
    fn get_instance() -> &'static SoftPcProTouchpadAccelerateCurves {
        static mut GLOBAL_CURVES: Option<SoftPcProTouchpadAccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(SoftPcProTouchpadAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.10, 0.18, 0.39, 0.75],
                        diff_nums: vec![0.0, -0.19, -5.25, -18.52]
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.14, 0.24, 0.52, 1.00],
                        diff_nums: vec![0.0, -0.25, -6.99, -24.69],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.17, 0.30, 0.64, 1.25],
                        diff_nums: vec![0.0, -0.32, -8.74, -30.86],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.21, 0.36, 0.77, 1.50],
                        diff_nums: vec![0.0, -0.38, -10.49, -37.03],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.28, 0.48, 1.03, 1.99],
                        diff_nums: vec![0.0, -0.51, -13.99, -49.38],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.34, 0.60, 1.29, 2.49],
                        diff_nums: vec![0.0, -0.63, -17.48, -61.72],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.41, 0.72, 1.55, 2.99],
                        diff_nums: vec![0.0, -0.76, -20.98, -74.06],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.52, 0.90, 1.93, 3.74],
                        diff_nums: vec![0.0, -0.95, -26.23, -92.58],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.65, 1.14, 2.45, 4.74],
                        diff_nums: vec![0.0, -0.86, -23.66, -83.51],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.79, 1.38, 2.96, 5.73],
                        diff_nums: vec![0.0, -1.45, -40.21, -141.96],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.93, 1.62, 3.48, 6.73],
                        diff_nums: vec![0.0, -1.71, -47.21, -166.64],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl HardPcProTouchpadAccelerateCurves {
    fn get_instance() -> &'static HardPcProTouchpadAccelerateCurves {
        static mut GLOBAL_CURVES: Option<HardPcProTouchpadAccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(HardPcProTouchpadAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.10, 0.17, 0.36, 0.69],
                        diff_nums: vec![0.0, -0.18, -4.84, -17.09]
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.13, 0.22, 0.48, 0.92],
                        diff_nums: vec![0.0, -0.23, -6.46, -22.79],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.16, 0.28, 0.59, 1.15],
                        diff_nums: vec![0.0, -0.29, -8.07, -28.49],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.19, 0.33, 0.71, 1.38],
                        diff_nums: vec![0.0, -0.35, -9.68, -34.18],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.25, 0.44, 0.95, 1.84],
                        diff_nums: vec![0.0, -0.47, -12.91, -45.58],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.32, 0.56, 1.19, 2.30],
                        diff_nums: vec![0.0, -0.58, -16.14, -56.97],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.38, 0.67, 1.43, 2.76],
                        diff_nums: vec![0.0, -0.70, -19.37, -68.37],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.48, 0.83, 1.78, 3.45],
                        diff_nums: vec![0.0, -0.88, -24.21, -85.46],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.60, 1.06, 2.26, 4.37],
                        diff_nums: vec![0.0, -1.11, -30.66, -108.25],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.73, 1.28, 2.74, 5.29],
                        diff_nums: vec![0.0, -1.34, -37.12, -131.04],
                    },
                    CurveItem {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.86, 1.50, 3.21, 6.21],
                        diff_nums: vec![0.0, -1.58, -43.58, -153.83],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl AxisAccelerateCurvesTouchpad {
    fn get_instance() -> &'static AxisAccelerateCurvesTouchpad {
        static mut GLOBAL_CURVES: Option<AxisAccelerateCurvesTouchpad> = None;
        static ONCE: Once = Once::new();
 
        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(AxisAccelerateCurvesTouchpad {
                data: vec![
                    CurveItem {
                        speeds: vec![3.0, 5.0, 6.0, 8.0, 10.0, 41.0],
                        slopes: vec![1.07, 0.80, 0.65, 0.55, 0.52, 0.81],
                        diff_nums: vec![0.0, 0.81, 1.56, 2.16, 2.4, -0.5]
                    },
                    CurveItem {
                        speeds: vec![0.36, 0.73, 1.46, 2.19, 2.92, 5.83, 10.94, 29.17],
                        slopes: vec![4.11, 2.83, 2.19, 1.69, 1.41, 1.87, 2.03, 2.03],
                        diff_nums: vec![0.0, 0.47, 0.93, 1.66, 2.28, 0.93, 0.0, 0.0]
                    },
                    CurveItem {
                        speeds: vec![0.36, 0.72, 1.45, 2.17, 2.89, 5.78, 10.84, 28.90],
                        slopes: vec![4.14, 2.85, 2.21, 1.72, 1.42, 1.88, 2.05, 2.05],
                        diff_nums: vec![0.0, 0.47, 0.93, 1.63, 2.28, 0.95, 0.0, 0.0]
                    },
                    CurveItem {
                        speeds: vec![0.36, 0.73, 1.46, 2.19, 2.92, 5.83, 10.94, 29.17],
                        slopes: vec![4.74, 3.28, 2.53, 1.95, 1.63, 1.63, 2.17, 2.35],
                        diff_nums: vec![0.0, 0.53, 1.08, 1.93, 2.63, 1.05, 0.0, 0.0]
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl TabletTouchpadAccelerateCurves {
    fn get_instance() -> &'static TabletTouchpadAccelerateCurves {
        static mut GLOBAL_CURVES: Option<TabletTouchpadAccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(TabletTouchpadAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.12, 0.21, 0.45, 0.87],
                        diff_nums: vec![0.0, -0.18, -4.98, -17.58]
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.16, 0.28, 0.60, 1.16],
                        diff_nums: vec![0.0, -0.24, -6.64, -23.44],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.20, 0.35, 0.75, 1.45],
                        diff_nums: vec![0.0, -0.30, -8.30, -29.30],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.24, 0.42, 0.90, 1.74],
                        diff_nums: vec![0.0, -0.36, -9.96, -35.16],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.32, 0.56, 1.20, 2.32],
                        diff_nums: vec![0.0, -0.48, -13.28, -46.88],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.40, 0.70, 1.50, 2.90],
                        diff_nums: vec![0.0, -0.60, -16.60, -58.60],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.48, 0.84, 1.80, 3.48],
                        diff_nums: vec![0.0, -0.72, -19.92, -70.32],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.60, 1.05, 2.25, 4.35],
                        diff_nums: vec![0.0, -0.90, -24.90, -87.90],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.76, 1.33, 2.85, 5.51],
                        diff_nums: vec![0.0, -1.14, -31.54, -111.34],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![0.92, 1.61, 3.45, 6.67],
                        diff_nums: vec![0.0, -1.38, -38.18, -134.78],
                    },
                    CurveItem {
                        speeds: vec![2.0, 20.0, 30.0, 128.0],
                        slopes: vec![1.08, 1.89, 4.05, 7.83],
                        diff_nums: vec![0.0, -1.62, -44.82, -158.22],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl FoldPcTouchpadAccelerateCurves {
    fn get_instance() -> &'static FoldPcTouchpadAccelerateCurves {
        static mut GLOBAL_CURVES: Option<FoldPcTouchpadAccelerateCurves> = None;
        static ONCE: Once = Once::new();
 
        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(FoldPcTouchpadAccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.08, 0.08, 0.19, 0.14, 0.15, 0.16, 0.15, 0.16, 0.65, 0.29, 1.05, 0.31],
                        diff_nums: vec![0.0, 0.0, -0.54, -0.03, -0.2, -0.45, -0.19, -0.8, -21.27, -3.61, -46.92, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.11, 0.11, 0.25, 0.18, 0.2, 0.21, 0.2, 0.22, 0.86, 0.38, 1.4, 0.41],
                        diff_nums: vec![0.0, 0.0, -0.72, -0.04, -0.27, -0.6, -0.25, -1.07, -28.37, -4.81, -62.56, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.14, 0.14, 0.31, 0.23, 0.25, 0.26, 0.25, 0.27, 1.08, 0.48, 1.74, 0.51],
                        diff_nums: vec![0.0, 0.0, -0.9, -0.05, -0.34, -0.75, -0.32, -1.34, -35.46, -6.02, -78.2, 0.0]
                    },  
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.17, 0.17, 0.37, 0.27, 0.29, 0.31, 0.3, 0.32, 1.29, 0.57, 2.09, 0.62],
                        diff_nums: vec![0.0, 0.0, -1.08, -0.06, -0.4, -0.9, -0.38, -1.61, -42.55, -7.22, -93.84, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.23, 0.23, 0.5, 0.36, 0.39, 0.42, 0.39, 0.43, 1.72, 0.76, 2.79, 0.82],
                        diff_nums: vec![0.0, 0.0, -1.44, -0.07, -0.54, -1.2, -0.51, -2.15, -56.73, -9.63, -125.12, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.28, 0.28, 0.62, 0.46, 0.49, 0.52, 0.49, 0.54, 2.15, 0.95, 3.49, 1.03],
                        diff_nums: vec![0.0, 0.0, -1.8, -0.09, -0.67, -1.5, -0.63, -2.68, -70.92, -12.03, -156.4, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.34, 0.34, 0.74, 0.55, 0.59, 0.63, 0.59, 0.65, 2.58, 1.14, 4.19, 1.24],
                        diff_nums: vec![0.0, 0.0, -2.16, -0.11, -0.81, -1.8, -0.76, -3.22, -85.1, -14.44, -187.68, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.42, 0.42, 0.93, 0.68, 0.74, 0.78, 0.74, 0.81, 3.23, 1.43, 5.23, 1.54],
                        diff_nums: vec![0.0, 0.0, -2.71, -0.14, -1.01, -2.24, -0.95, -4.02, -106.37, -18.05, -234.59, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.54, 0.54, 1.18, 0.87, 0.93, 0.99, 0.94, 1.03, 4.09, 1.81, 6.63, 1.96],
                        diff_nums: vec![0.0, 0.0, -3.43, -0.18, -1.28, -2.84, -1.2, -5.09, -134.74, -22.86, -297.15, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.65, 0.65, 1.42, 1.05, 1.13, 1.2, 1.13, 1.25, 4.95, 2.19, 8.02, 2.37],
                        diff_nums: vec![0.0, 0.0, -4.15, -0.21, -1.55, -3.44, -1.46, -6.17, -163.11, -27.67, -359.71, 0.0]
                    },
                    CurveItem {
                        speeds: vec![2.68, 5.36, 10.49, 16.96, 25.66, 29.01, 41.95, 42.4, 49.1, 56.91, 63.6, 93.73],
                        slopes: vec![0.76, 0.76, 1.67, 1.23, 1.32, 1.41, 1.33, 1.46, 5.81, 2.57, 9.42, 2.78],
                        diff_nums: vec![0.0, 0.0, -4.87, -0.25, -1.82, -4.04, -1.71, -7.24, -191.47, -32.49, -422.27, 0.0]
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}
// 这个 extern 代码块链接到 libm 库
#[link(name = "m")]
extern {
    fn fabs(z: f64) -> f64;
    fn fmax(a: f64, b: f64) -> f64;
    fn fmin(a: f64, b: f64) -> f64;
}

fn get_speed_dynamic_gain_mouse(vin: f64, gain: *mut f64, speed: i32, delta_time: u64, display_ppi: f64) -> bool {
    debug!(LOG_LABEL, "get_speed_gain_mouse enter vin is set to {} speed {}, delta_time {}, display_ppi {}",
    @public(vin), @public(speed), @public(delta_time), @public(display_ppi));
    if delta_time < 1 {
        error!(LOG_LABEL, "{} The delta_time can't be less than 0", @public(delta_time));
        return false;
    }
    if display_ppi < 1.0 {
        error!(LOG_LABEL, "{} The display_ppi can't be less than 1", @public(display_ppi));
        return false;
    }
    unsafe {
        if fabs(vin) < DOUBLE_ZERO {
            error!(LOG_LABEL, "{} less that the limit", DOUBLE_ZERO);
            return false;
        }
    }
    if speed < 1 {
        error!(LOG_LABEL, "{} The speed value can't be less than 1", @public(speed));
        return false;
    }
    let speeds_radio = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
                        1.2, 1.4, 1.6, 1.8, 2.0, 2.2, 2.4, 2.6, 2.8, 3.0];
    let standard_slopes = [2.9394, 3.7879, 8.2121, 13.1515];
    let vins = [0.50, 1.30, 2.20, 16.17];
    unsafe {
        let vin_new: f64 = vin * MS_2_US / delta_time as f64;
        let speed_radio = speeds_radio[speed as usize - 1];
        let mut slopes = Vec::new();
        let mut diff_nums = Vec::new();
        for i in 0..4 {
            slopes.push(standard_slopes[i] * display_ppi / MOUSE_DPI);
            if i < 1 {
                diff_nums.push(0.0);
                continue;
            }
            diff_nums.push((slopes[i - 1] - slopes[i]) * vins[i - 1] + diff_nums[i - 1]);
        }
        let num: f64 = fabs(vin_new);
        for i in 0..4 {
            if num <= vins[i] {
                *gain = (slopes[i] * vin_new + diff_nums[i]) * speed_radio / vin_new;
                debug!(LOG_LABEL, "gain is set to {}", @public(slopes[i]));
                return true;
            }
        }
        *gain = (slopes[3] * vin_new + diff_nums[3]) * speed_radio / vin_new;
        debug!(LOG_LABEL, "gain is set to {}", @public(slopes[3]));
    }
    debug!(LOG_LABEL, "get_speed_gain_mouse leave");
    true
}

fn get_speed_gain_mouse(vin: f64, gain: *mut f64, speed: i32, device_type: i32) -> bool {
    debug!(LOG_LABEL, "get_speed_gain_mouse enter vin is set to {} speed {}, device_type {}",
        @public(vin), @public(speed), @public(device_type));
    unsafe {
        if fabs(vin) < DOUBLE_ZERO {
            error!(LOG_LABEL, "{} less that the limit", DOUBLE_ZERO);
            return false;
        }
    }
    if speed < 1 {
        error!(LOG_LABEL, "{} The speed value can't be less than 1", @public(speed));
        return false;
    }
    let item = match device_type {  
        1 => PCMouseAccelerateCurves::get_instance().pc_mouse_get_curve_by_speed(speed as usize),  
        2 => SoftPcProMouseAccelerateCurves::get_instance().soft_pc_pro_mouse_get_curve_by_speed(speed as usize),  
        3 => HardPcProMouseAccelerateCurves::get_instance().hard_pc_pro_mouse_get_curve_by_speed(speed as usize),  
        _ => PCMouseAccelerateCurves::get_instance().pc_mouse_get_curve_by_speed(speed as usize),
    };
    unsafe {
        let num: f64 = fabs(vin);
        let len = item.speeds.len();
        for i in 0..len {
            if num <= item.speeds[i] {
                *gain = (item.slopes[i] * vin + item.diff_nums[i]) / vin;
                debug!(LOG_LABEL, "slope is set to {}, gain is {}", @public(item.slopes[i]), @public(*gain));
                return true;
            }
        }
        *gain = (item.slopes[len - 1] * vin + item.diff_nums[len - 1]) / vin;
        debug!(LOG_LABEL, "slope is set to {}, gain is {}", @public(item.slopes[len - 1]), @public(*gain));
    }
    debug!(LOG_LABEL, "get_speed_gain_mouse leave");
    true
}


fn get_speed_gain_touchpad(vin: f64, gain: *mut f64, speed: i32, device_type: i32) -> bool {
    debug!(LOG_LABEL, "get_speed_gain_touchpad enter vin is set to {}, speed {}, device_type {}",
        @public(vin), @public(speed), @public(device_type));
    unsafe {
        if fabs(vin) < DOUBLE_ZERO {
            error!(LOG_LABEL, "{} less that the limit", DOUBLE_ZERO);
            return false;
        }
    }
    if speed < 1 {
        error!(LOG_LABEL, "{} The speed value can't be less than 1", @public(speed));
        return false;
    }
    let item = match device_type {  
        1 => PCTouchpadAccelerateCurves::get_instance().pc_touchpad_get_curve_by_speed(speed as usize),  
        2 => SoftPcProTouchpadAccelerateCurves::get_instance().soft_pc_pro_touchpad_get_curve_by_speed(speed as usize),  
        3 => HardPcProTouchpadAccelerateCurves::get_instance().hard_pc_pro_touchpad_get_curve_by_speed(speed as usize),  
        4 => TabletTouchpadAccelerateCurves::get_instance().tablet_touchpad_get_curve_by_speed(speed as usize),
        5 => FoldPcTouchpadAccelerateCurves::get_instance().fold_pc_touchpad_get_curve_by_speed(speed as usize),
        _ => PCTouchpadAccelerateCurves::get_instance().pc_touchpad_get_curve_by_speed(speed as usize),
    };
    unsafe {
        let num: f64 = fabs(vin);
        let len = item.speeds.len();
        for i in 0..len {
            if num <= item.speeds[i] {
                *gain = (item.slopes[i] * num + item.diff_nums[i]) / num;
                debug!(LOG_LABEL, "gain is set to {}", @public((*gain * num - item.diff_nums[i]) / num));
                return true;
            }
        }
        *gain = (item.slopes[len-1] * num + item.diff_nums[len-1]) / num;
        debug!(LOG_LABEL, "gain is set to {}", @public((*gain * num - item.diff_nums[len-1]) / num));
    }
    debug!(LOG_LABEL, "get_speed_gain_touchpad leave");
    true
}

fn get_axis_gain_touchpad(gain: *mut f64, axis_speed: f64, device_type: i32) -> bool {
    debug!(LOG_LABEL, "get_axis_gain_touchpad enter axis_speed is set to {}, device_type {}",
        @public(axis_speed), @public(device_type));
    let valid_device_type = match device_type {
        1..=2 => device_type,
        4 => 3,
        5 => 4,
        _ => 1,
    };
    let item = AxisAccelerateCurvesTouchpad::get_instance().get_axis_curve_by_speed_touchpad(valid_device_type as usize);
    unsafe {
        let num: f64 = fabs(axis_speed);
        let len = item.speeds.len();
        for i in 0..len {
            if num <= item.speeds[i] {
                *gain = item.slopes[i] * num + item.diff_nums[i];
                debug!(LOG_LABEL, "gain is set to {}", @public((*gain - item.diff_nums[i]) / num));
                return true;
            }
        }
        *gain = item.slopes[len - 1] * num + item.diff_nums[len - 1];
        debug!(LOG_LABEL, "gain is set to {}", @public((*gain - item.diff_nums[len - 1]) / num));
    }
    debug!(LOG_LABEL, "get_axis_gain_touchpad leave");
    true
}

/// Offset struct is defined in C++, which give the vlaue
/// dx = libinput_event_pointer_get_dx
/// dy = libinput_event_pointer_get_dy
#[repr(C)]
pub struct Offset {
    dx: f64,
    dy: f64,
}

/// # Safety
/// HandleMotionDynamicAccelerateMouse is the origin C++ function name
/// C++ will call for rust realization using this name
#[no_mangle]
pub unsafe extern "C" fn HandleMotionDynamicAccelerateMouse (
    offset: *const Offset,
    mode: bool,
    abs_x: *mut f64,
    abs_y: *mut f64,
    speed: i32,
    delta_time: u64,
    display_ppi: f64
) -> i32 {
    let mut gain = 0.0;
    let vin: f64;
    let dx: f64;
    let dy: f64;
    unsafe {
        dx = (*offset).dx;
        dy = (*offset).dy;
        vin = (fmax(fabs(dx), fabs(dy))) + (fmin(fabs(dx), fabs(dy))) / 2.0;
        debug!(
            LOG_LABEL,
            "output the abs_x {} and abs_y {} captureMode {} dx {} dy {} gain {}",
            @private(*abs_x),
            @private(*abs_y),
            @public(mode),
            @private(dx),
            @private(dy),
            @public(gain)
        );
        if !get_speed_dynamic_gain_mouse(vin, &mut gain as *mut f64, speed, delta_time, display_ppi) {
            error!(LOG_LABEL, "{} getSpeedGgain failed!", @public(speed));
            return RET_ERR;
        }
        if !mode {
            *abs_x += dx * gain;
            *abs_y += dy * gain;
        }
        debug!(
            LOG_LABEL,
            "abs_x {} and abs_y {}", @private(*abs_x), @private(*abs_y)
        );
    }
    RET_OK
}

/// # Safety
/// HandleMotionAccelerateMouse is the origin C++ function name
/// C++ will call for rust realization using this name
#[no_mangle]
pub unsafe extern "C" fn HandleMotionAccelerateMouse (
    offset: *const Offset,
    mode: bool,
    abs_x: *mut f64,
    abs_y: *mut f64,
    speed: i32,
    device_type: i32
) -> i32 {
    let mut gain = 0.0;
    let vin: f64;
    let dx: f64;
    let dy: f64;
    unsafe {
        dx = (*offset).dx;
        dy = (*offset).dy;
        vin = (fmax(fabs(dx), fabs(dy))) + (fmin(fabs(dx), fabs(dy))) / 2.0;
        debug!(
            LOG_LABEL,
            "output the abs_x {} and abs_y {} captureMode {} dx {} dy {} gain {}",
            @private(*abs_x),
            @private(*abs_y),
            @public(mode),
            @private(dx),
            @private(dy),
            @public(gain)
        );
        if !get_speed_gain_mouse(vin, &mut gain as *mut f64, speed, device_type) {
            error!(LOG_LABEL, "{} getSpeedGgain failed!", @public(speed));
            return RET_ERR;
        }
        if !mode {
            *abs_x += dx * gain;
            *abs_y += dy * gain;
        }
        debug!(
            LOG_LABEL,
            "abs_x {} and abs_y {}", @private(*abs_x), @private(*abs_y)
        );
    }
    RET_OK
}

/// # Safety
/// HandleMotionAccelerateTouchpad is the origin C++ function name
/// C++ will call for rust realization using this name
#[no_mangle]
pub unsafe extern "C" fn HandleMotionAccelerateTouchpad (
    offset: *const Offset,
    mode: bool,
    abs_x: *mut f64,
    abs_y: *mut f64,
    speed: i32,
    device_type: i32
) -> i32 {
    let mut gain = 0.0;
    let vin: f64;
    let dx: f64;
    let dy: f64;
    let deltax: f64;
    let deltay: f64;
    unsafe {
        dx = (*offset).dx;
        dy = (*offset).dy;
        vin = (fmax(fabs(dx), fabs(dy))) + (fmin(fabs(dx), fabs(dy))) / 2.0;
        debug!(
            LOG_LABEL,
            "output the abs_x {} and abs_y {} captureMode {} dx {} dy {} gain {}",
            @private(*abs_x),
            @private(*abs_y),
            @public(mode),
            @private(dx),
            @private(dy),
            @public(gain)
        );
        if !get_speed_gain_touchpad(vin, &mut gain as *mut f64, speed, device_type) {
            error!(LOG_LABEL, "{} getSpeedGgain failed!", @public(speed));
            return RET_ERR;
        }
        if !mode {
            deltax = (dx * gain + COMPENSATE_VALUEX).trunc();
            deltay = (dy * gain + COMPENSATE_VALUEY).trunc();
            COMPENSATE_VALUEX = (dx * gain + COMPENSATE_VALUEX).fract();
            COMPENSATE_VALUEY = (dy * gain + COMPENSATE_VALUEY).fract();
            *abs_x += deltax;
            *abs_y += deltay;
        }
        debug!(
            LOG_LABEL,
            "output the abs_x {} and abs_y {}", @private(*abs_x), @private(*abs_y)
        );
    }
    RET_OK
}

/// # Safety
/// HandleAxisAccelerateTouchpad is the origin C++ function name
/// C++ will call for rust realization using this name
#[no_mangle]
pub unsafe extern "C" fn HandleAxisAccelerateTouchpad (
    mode: bool,
    abs_axis: *mut f64,
    device_type: i32
) -> i32 {
    let mut gain = 0.0;
    unsafe {
        debug!(
            LOG_LABEL,
            "input the abs_axis {} and captureMode {} gain {}",
            @public(*abs_axis),
            @public(mode),
            @public(gain)
        );
        if !get_axis_gain_touchpad(&mut gain as *mut f64, *abs_axis, device_type) {
            error!(LOG_LABEL, "{} getAxisGain failed!", @public(*abs_axis));
            return RET_ERR;
        }
        if !mode {
            *abs_axis = if *abs_axis >= 0.0 { gain } else { -gain };
        }
        debug!(
            LOG_LABEL,
            "output the abs_axis {}", @public(*abs_axis)
        );
    }
    RET_OK
}

#[test]
fn test_handle_motion_accelerate_normal()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateMouse(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 0);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_mini_limit()
{
    let offset: Offset = Offset{ dx: 0.00000001, dy: 0.00000002 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateMouse(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 0);
    }
    assert_eq!(ret, RET_ERR);
}

#[test]
fn test_handle_motion_accelerate_capture_mode_false()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateMouse(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 0);
    }
    assert_eq!(ret, RET_OK);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

/* test for touchpad */
#[test]
fn test_handle_motion_accelerate_normal_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 0);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_mini_limit_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00000001, dy: 0.00000002 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 0);
    }
    assert_eq!(ret, RET_ERR);
}

#[test]
fn test_handle_motion_accelerate_capture_mode_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 0);
    }
    assert_eq!(ret, RET_OK);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

/* test for touchpad pc */
#[test]
fn test_handle_motion_accelerate_capture_pc_offset_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00000001, dy: 0.00000002 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 1);
    }
    assert_eq!(ret, RET_ERR);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

#[test]
fn test_handle_motion_accelerate_capture_pc_speed_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 0, 1);
    }
    assert_eq!(ret, RET_ERR);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

#[test]
fn test_handle_motion_accelerate_capture_pc_mode_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 1);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_capture_pc_nomarl_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 1);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_capture_pc_offset_exceed_max_touchpad()
{
    let offset: Offset = Offset{ dx: 82.00002, dy: 82.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 1);
    }
    assert_eq!(ret, RET_OK);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

/* test for touchpad soft_pc_pro */
#[test]
fn test_handle_motion_accelerate_capture_soft_pc_pro_offset_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00000001, dy: 0.00000002 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 2);
        debug!(
        LOG_LABEL,
        "ret = {}", @public(ret)
        );
    }
    assert_eq!(ret, RET_ERR);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

#[test]
fn test_handle_motion_accelerate_capture_soft_pc_pro_speed_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 0, 2);
    }
    assert_eq!(ret, RET_ERR);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

#[test]
fn test_handle_motion_accelerate_capture_soft_pc_pro_mode_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 2);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_capture_soft_pc_pro_nomarl_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 2);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_capture_soft_pc_pro_offset_exceed_max_touchpad()
{
    let offset: Offset = Offset{ dx: 160.00002, dy: 160.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 2);
    }
    assert_eq!(ret, RET_OK);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

/* test for touchpad hard_pc_pro */
#[test]
fn test_handle_motion_accelerate_capture_hard_pc_pro_offset_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00000001, dy: 0.00000002 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 3);
    }
    assert_eq!(ret, RET_ERR);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

#[test]
fn test_handle_motion_accelerate_capture_hard_pc_pro_speed_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 0, 3);
    }
    assert_eq!(ret, RET_ERR);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

#[test]
fn test_handle_motion_accelerate_capture_hard_pc_pro_mode_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 3);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_capture_hard_pc_pro_nomarl_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00002, dy: 1.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 3);
    }
    assert_eq!(ret, RET_OK);
}

#[test]
fn test_handle_motion_accelerate_capture_hard_pc_pro_offset_exceed_max_touchpad()
{
    let offset: Offset = Offset{ dx: 160.00002, dy: 160.00004 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 3);
    }
    assert_eq!(ret, RET_OK);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}
/* test touchpad axis */
#[test]
fn test_handle_axis_accelerate_normal_touchpad()
{
    let mut abs_axis: f64 = 19.29931034482759;
    let ret: i32;
    unsafe {
        ret = HandleAxisAccelerateTouchpad(false, &mut abs_axis as *mut f64, 1);
    }
    assert_eq!(ret, RET_OK);
}
 
#[test]
fn test_handle_axis_accelerate_capture_mode_false_touchpad()
{
    let mut abs_axis: f64 = 19.29931034482759;
    let ret: i32;
    unsafe {
        ret = HandleAxisAccelerateTouchpad(true, &mut abs_axis as *mut f64, 1);
    }
    assert_eq!(ret, RET_OK);
}
