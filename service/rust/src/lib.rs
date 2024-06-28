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

struct CurveItem {
    pub speeds: Vec<i32>,
    pub slopes: Vec<f64>,
    pub diff_nums: Vec<f64>,
}
struct CurveItemTouchpad {
    pub speeds: Vec<f64>,
    pub slopes: Vec<f64>,
    pub diff_nums: Vec<f64>,
}
struct AxisCurveItemTouchpad {
    pub speeds: Vec<f64>,
    pub slopes: Vec<f64>,
    pub diff_nums: Vec<f64>,
}
struct AccelerateCurves {
    data: Vec<CurveItem>,
}
struct AccelerateCurvesKLV {
    data: Vec<CurveItemTouchpad>,
}
struct AccelerateCurvesSoftHarden {
    data: Vec<CurveItemTouchpad>,
}
struct AccelerateCurvesHardHarden {
    data: Vec<CurveItemTouchpad>,
}
struct AxisAccelerateCurvesTouchpad {
    data: Vec<AxisCurveItemTouchpad>,
}
impl AccelerateCurves {
    fn get_curve_by_speed(&self, speed: usize) -> &CurveItem {
        &self.data[speed - 1]
    }
}
impl AccelerateCurvesKLV {
    fn get_curve_by_speed_klv(&self, speed: usize) -> &CurveItemTouchpad {
        &self.data[speed - 1]
    }
}
impl AccelerateCurvesSoftHarden {
    fn get_curve_by_speed_soft_harden(&self, speed: usize) -> &CurveItemTouchpad {
        &self.data[speed - 1]
    }
}
impl AccelerateCurvesHardHarden {
    fn get_curve_by_speed_hard_harden(&self, speed: usize) -> &CurveItemTouchpad {
        &self.data[speed - 1]
    }
}
impl AxisAccelerateCurvesTouchpad {
    fn get_axis_curve_by_speed_touchpad(&self, device_type: usize) -> &AxisCurveItemTouchpad {
        &self.data[device_type - 1]
    }
}
impl AccelerateCurves {
    fn get_instance() -> &'static AccelerateCurves {
        static mut GLOBAL_CURVES: Option<AccelerateCurves> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(AccelerateCurves {
                data: vec![
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![0.16, 0.30, 0.56],
                        diff_nums: vec![0.0, -1.12, -9.44],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![0.32, 0.60, 1.12],
                        diff_nums: vec![0.0, -2.24, -18.88],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![0.64, 1.2, 2.24],
                        diff_nums: vec![0.0, -4.48, -37.76],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![0.80, 1.50, 2.80],
                        diff_nums: vec![0.0, -5.6, -47.2],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![0.92, 2.40, 4.48],
                        diff_nums: vec![0.0, -11.84, -78.4],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![1.04, 3.30, 6.16],
                        diff_nums: vec![0.0, -18.08, -109.60],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![1.10, 3.75, 7.00],
                        diff_nums: vec![0.0, -21.2, -125.20],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![1.16, 4.20, 7.84],
                        diff_nums: vec![0.0, -24.32, -140.8],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![1.22, 4.65, 8.68],
                        diff_nums: vec![0.0, -27.44, -156.40],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![1.28, 5.1, 9.52],
                        diff_nums: vec![0.0, -30.56, -172.00],
                    },
                    CurveItem {
                        speeds: vec![8, 32, 128],
                        slopes: vec![1.34, 5.55, 10.36],
                        diff_nums: vec![0.0, -33.68, -187.6],
                    },
                ],
            });
        });
        unsafe { GLOBAL_CURVES.as_ref().unwrap() }
    }
}

impl AccelerateCurvesKLV {
    fn get_instance() -> &'static AccelerateCurvesKLV {
        static mut GLOBAL_CURVES: Option<AccelerateCurvesKLV> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(AccelerateCurvesKLV {
                data: vec![
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.14, 0.25, 0.53, 1.03],
                        diff_nums: vec![0.0, -0.14, -3.74, -13.19]
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.19, 0.33, 0.71, 1.37],
                        diff_nums: vec![0.0, -0.18, -4.98, -17.58],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.24, 0.41, 0.88, 1.71],
                        diff_nums: vec![0.0, -0.21, -5.91, -20.88],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.28, 0.49, 1.06, 2.05],
                        diff_nums: vec![0.0, -0.27, -7.47, -26.37],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.38, 0.66, 1.41, 2.73],
                        diff_nums: vec![0.0, -0.36, -9.96, -35.16],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.47, 0.82, 1.77, 3.42],
                        diff_nums: vec![0.0, -0.45, -12.45, -43.95],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.57, 0.99, 2.12, 4.10],
                        diff_nums: vec![0.0, -0.54, -14.94, -52.74],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.71, 1.24, 2.65, 5.13],
                        diff_nums: vec![0.0, -0.68, -18.68, -65.93],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![0.90, 1.57, 3.36, 6.49],
                        diff_nums: vec![0.0, -0.86, -23.66, -83.51],
                    },
                    CurveItemTouchpad {
                        speeds: vec![1.27, 12.73, 19.09, 81.46],
                        slopes: vec![1.08, 1.90, 4.07, 7.86],
                        diff_nums: vec![0.0, -1.04, -28.64, -101.09],
                    },
                    CurveItemTouchpad {
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

impl AccelerateCurvesSoftHarden {
    fn get_instance() -> &'static AccelerateCurvesSoftHarden {
        static mut GLOBAL_CURVES: Option<AccelerateCurvesSoftHarden> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(AccelerateCurvesSoftHarden {
                data: vec![
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.10, 0.18, 0.39, 0.75],
                        diff_nums: vec![0.0, -0.19, -5.25, -18.52]
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.14, 0.24, 0.52, 1.00],
                        diff_nums: vec![0.0, -0.25, -6.99, -24.69],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.17, 0.30, 0.64, 1.25],
                        diff_nums: vec![0.0, -0.32, -8.74, -30.86],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.21, 0.36, 0.77, 1.50],
                        diff_nums: vec![0.0, -0.38, -10.49, -37.03],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.28, 0.48, 1.03, 1.99],
                        diff_nums: vec![0.0, -0.51, -13.99, -49.38],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.34, 0.60, 1.29, 2.49],
                        diff_nums: vec![0.0, -0.63, -17.48, -61.72],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.41, 0.72, 1.55, 2.99],
                        diff_nums: vec![0.0, -0.76, -20.98, -74.06],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.52, 0.90, 1.93, 3.74],
                        diff_nums: vec![0.0, -0.95, -26.23, -92.58],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.65, 1.14, 2.45, 4.74],
                        diff_nums: vec![0.0, -0.86, -23.66, -83.51],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.79, 1.38, 2.96, 5.73],
                        diff_nums: vec![0.0, -1.45, -40.21, -141.96],
                    },
                    CurveItemTouchpad {
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

impl AccelerateCurvesHardHarden {
    fn get_instance() -> &'static AccelerateCurvesHardHarden {
        static mut GLOBAL_CURVES: Option<AccelerateCurvesHardHarden> = None;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            GLOBAL_CURVES = Some(AccelerateCurvesHardHarden {
                data: vec![
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.10, 0.17, 0.36, 0.69],
                        diff_nums: vec![0.0, -0.18, -4.84, -17.09]
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.13, 0.22, 0.48, 0.92],
                        diff_nums: vec![0.0, -0.23, -6.46, -22.79],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.16, 0.28, 0.59, 1.15],
                        diff_nums: vec![0.0, -0.29, -8.07, -28.49],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.19, 0.33, 0.71, 1.38],
                        diff_nums: vec![0.0, -0.35, -9.68, -34.18],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.25, 0.44, 0.95, 1.84],
                        diff_nums: vec![0.0, -0.47, -12.91, -45.58],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.32, 0.56, 1.19, 2.30],
                        diff_nums: vec![0.0, -0.58, -16.14, -56.97],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.38, 0.67, 1.43, 2.76],
                        diff_nums: vec![0.0, -0.70, -19.37, -68.37],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.48, 0.83, 1.78, 3.45],
                        diff_nums: vec![0.0, -0.88, -24.21, -85.46],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.60, 1.06, 2.26, 4.37],
                        diff_nums: vec![0.0, -1.11, -30.66, -108.25],
                    },
                    CurveItemTouchpad {
                        speeds: vec![2.45, 24.51, 36.77, 156.87],
                        slopes: vec![0.73, 1.28, 2.74, 5.29],
                        diff_nums: vec![0.0, -1.34, -37.12, -131.04],
                    },
                    CurveItemTouchpad {
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
                    AxisCurveItemTouchpad {
                        speeds: vec![3.0, 5.0, 6.0, 8.0, 10.0, 41.0],
                        slopes: vec![1.07, 0.80, 0.65, 0.55, 0.52, 0.81],
                        diff_nums: vec![0.0, 0.81, 1.56, 2.16, 2.4, -0.5]
                    },
                    AxisCurveItemTouchpad {
                        speeds: vec![1.0, 3.0, 5.0, 6.0, 7.0, 8.0, 41.0],
                        slopes: vec![1.52, 0.96, 0.71, 0.57, 0.47, 0.67, 0.75],
                        diff_nums: vec![0.0, 0.56, 1.31, 2.01, 2.61, 1.21, 0.57]
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
    fn ceil(z: f64) -> f64;
    fn fmax(a: f64, b: f64) -> f64;
    fn fmin(a: f64, b: f64) -> f64;
}

fn get_speed_gain(vin: f64, gain: *mut f64, speed: i32) -> bool {
    debug!(LOG_LABEL, "get_speed_gain enter vin is set to {} speed {} ", @public(vin), @public(speed));
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
    let item = AccelerateCurves::get_instance().get_curve_by_speed(speed as usize);
    unsafe {
        let num: i32 = ceil(fabs(vin)) as i32;
        for i in 0..3 {
            if num <= item.speeds[i] {
                *gain = (item.slopes[i] * vin + item.diff_nums[i]) / vin;
                debug!(LOG_LABEL, "gain is set to {}", @public((*gain * vin - item.diff_nums[i])/ vin));
                return true;
            }
        }
        *gain = (item.slopes[2] * vin + item.diff_nums[2]) / vin;
        debug!(LOG_LABEL, "gain is set to {}", @public((*gain * vin - item.diff_nums[2])/ vin));
    }
    debug!(LOG_LABEL, "get_speed_gain leave");
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
        1 => AccelerateCurvesKLV::get_instance().get_curve_by_speed_klv(speed as usize),  
        2 => AccelerateCurvesSoftHarden::get_instance().get_curve_by_speed_soft_harden(speed as usize),  
        3 => AccelerateCurvesHardHarden::get_instance().get_curve_by_speed_hard_harden(speed as usize),  
        _ => AccelerateCurvesKLV::get_instance().get_curve_by_speed_klv(speed as usize),
    };
    unsafe {
        let num: f64 = fabs(vin);
        for i in 0..4 {
            if num <= item.speeds[i] {
                *gain = (item.slopes[i] * vin + item.diff_nums[i]) / vin;
                debug!(LOG_LABEL, "gain is set to {}", @public((*gain * vin - item.diff_nums[i])/ vin));
                return true;
            }
        }
        *gain = (item.slopes[3] * vin + item.diff_nums[3]) / vin;
        debug!(LOG_LABEL, "gain is set to {}", @public((*gain * vin - item.diff_nums[3])/ vin));
    }
    debug!(LOG_LABEL, "get_speed_gain_touchpad leave");
    true
}

fn get_axis_gain_touchpad(gain: *mut f64, axis_speed: f64, device_type: i32) -> bool {
    debug!(LOG_LABEL, "get_axis_gain_touchpad enter axis_speed is set to {}, device_type {}",
        @public(axis_speed), @public(device_type));
    let valid_device_type = match device_type {
        1..=2 => device_type,
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
/// HandleMotionAccelerate is the origin C++ function name
/// C++ will call for rust realization using this name
#[no_mangle]
pub unsafe extern "C" fn HandleMotionAccelerate (
    offset: *const Offset,
    mode: bool,
    abs_x: *mut f64,
    abs_y: *mut f64,
    speed: i32,
) -> i32 {
    let mut gain = 0.0;
    let vin: f64;
    let dx: f64;
    let dy: f64;
    unsafe {
        dx = (*offset).dx;
        dy = (*offset).dy;
        vin = (fmax(fabs(dx), fabs(dy)) + fmin(fabs(dx), fabs(dy))) / 2.0;
        debug!(
            LOG_LABEL,
            "output the abs_x {} and abs_y {} captureMode {} dx {} dy {} gain {}",
            @public(*abs_x),
            @public(*abs_y),
            @public(mode),
            @public(dx),
            @public(dy),
            @public(gain)
        );
        if !get_speed_gain(vin, &mut gain as *mut f64, speed) {
            error!(LOG_LABEL, "{} getSpeedGgain failed!", @public(speed));
            return RET_ERR;
        }
        if !mode {
            *abs_x += dx * gain;
            *abs_y += dy * gain;
        }
        debug!(
            LOG_LABEL,
            "abs_x {} and abs_y {}", @public(*abs_x), @public(*abs_y)
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
            @public(*abs_x),
            @public(*abs_y),
            @public(mode),
            @public(dx),
            @public(dy),
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
            "output the abs_x {} and abs_y {}", @public(*abs_x), @public(*abs_y)
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
        ret = HandleMotionAccelerate(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2);
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
        ret = HandleMotionAccelerate(&offset, false, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2);
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
        ret = HandleMotionAccelerate(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2);
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

/* test for touchpad klv */
#[test]
fn test_handle_motion_accelerate_capture_klv_offset_false_touchpad()
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
fn test_handle_motion_accelerate_capture_klv_speed_false_touchpad()
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
fn test_handle_motion_accelerate_capture_klv_mode_false_touchpad()
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
fn test_handle_motion_accelerate_capture_klv_nomarl_touchpad()
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
fn test_handle_motion_accelerate_capture_klv_offset_exceed_max_touchpad()
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

/* test for touchpad soft_harden */
#[test]
fn test_handle_motion_accelerate_capture_soft_harden_offset_false_touchpad()
{
    let offset: Offset = Offset{ dx: 0.00000001, dy: 0.00000002 };
    let mut abs_x: f64 = 0.0;
    let mut abs_y: f64 = 0.0;
    let ret: i32;
    unsafe {
        ret = HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x as *mut f64, &mut abs_y as *mut f64, 2, 2);
        debug!(
        LOG_LABEL,
        "ret =  {}", @public(ret)
        );
    }
    assert_eq!(ret, RET_ERR);
    assert_eq!(abs_x, 0.0);
    assert_eq!(abs_y, 0.0);
}

#[test]
fn test_handle_motion_accelerate_capture_soft_harden_speed_false_touchpad()
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
fn test_handle_motion_accelerate_capture_soft_harden_mode_false_touchpad()
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
fn test_handle_motion_accelerate_capture_soft_harden_nomarl_touchpad()
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
fn test_handle_motion_accelerate_capture_soft_harden_offset_exceed_max_touchpad()
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

/* test for touchpad hard_harden */
#[test]
fn test_handle_motion_accelerate_capture_hard_harden_offset_false_touchpad()
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
fn test_handle_motion_accelerate_capture_hard_harden_speed_false_touchpad()
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
fn test_handle_motion_accelerate_capture_hard_harden_mode_false_touchpad()
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
fn test_handle_motion_accelerate_capture_hard_harden_nomarl_touchpad()
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
fn test_handle_motion_accelerate_capture_hard_harden_offset_exceed_max_touchpad()
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
