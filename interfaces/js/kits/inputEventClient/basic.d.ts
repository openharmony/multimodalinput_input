/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

export interface Callback<T> {
     /**
     * 
     * The common event management service callback.
     * 
     * @devices phone, tablet
     * @since 3
     * @SysCap ces
     * @param data Indicate the common event data.
     * @return -
     */
    (data: T): void;
}

export interface AsyncCallback<T> {
    /**
     * 
     * The common event management service callback.
     * 
     * @devices phone, tablet
     * @since 3
     * @SysCap ces
     * @param err Indicate the bussiness error code.
     * @param data Indicate the common event data.
     * @return -
     */
    (err: BussinessError, data: T): void;
}

export interface BussinessError extends Error {
    /**
     * The bussiness error code.
     *
     * @default -
     * @devices phone, tablet
     * @since 3
     * @SysCap ces
     */
    code: number;
}

export interface ErrorCallback {
    /**
     * 
     * The common event management service error callback.
     * 
     * @devices phone, tablet
     * @since 3
     * @SysCap ces
     * @param err Indicate the error.
     * @return -
     */
    (err: Error): void;
}