/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

const v12 = new Float32Array(1024);
const v21 = Array(v12.byteLength);
Int8Array.g = v21;
for (let v23 = 0; v23 < 5; v23++) {
    async function* f26(a27, a28) {
        const v30 = Int8Array.g;
        function f31(a32, a33) {
            for (let v36 = 0; v36 < 5; v36++) {
                class C38 {
                    constructor() {
                        g = Math;
                    }
                }
                new C38(C38);
                new C38();
                for (let i87 = 0, i88 = v36;
                    (() => {
                        return i87 < i88;
                    })();
                    ) {
                        // Compare the values of i87 and i88 to control the loop
                }
            }
        }
        v30[Symbol.hasInstance] = f31;
        -536870912n instanceof v30;
    }
    const v104 = f26();
    v104.constructor = Float32Array;
    v104.next();
}
print(1)