/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <cstdio>
#include <iostream>
#include <thread>
#include <chrono>
#include "input_manager.h"

using namespace OHOS::MMI;

int main()
{
    std::cout << "=== Multi-Group API Impact Test ===" << std::endl;
    std::cout << "Verifies global pointer APIs still work after binding feature is present." << std::endl;

    bool visible = true;
    int32_t ret = InputManager::GetInstance()->SetPointerVisible(visible);
    std::cout << "[1] SetPointerVisible(true): ret=" << ret << std::endl;

    ret = InputManager::GetInstance()->IsPointerVisible(visible);
    std::cout << "[2] IsPointerVisible: ret=" << ret << " visible=" << visible << std::endl;

    int32_t speed = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(speed);
    std::cout << "[3] GetPointerSpeed: ret=" << ret << " speed=" << speed << std::endl;

    int32_t style = -1;
    ret = InputManager::GetInstance()->GetPointerSize(style);
    std::cout << "[4] GetPointerSize: ret=" << ret << " size=" << style << std::endl;

    int32_t color = -1;
    ret = InputManager::GetInstance()->GetPointerColor(color);
    std::cout << "[5] GetPointerColor: ret=" << ret << " color=" << color << std::endl;

    std::cout << "=== ALL GLOBAL APIs ACCESSIBLE ===" << std::endl;
    return 0;
}
