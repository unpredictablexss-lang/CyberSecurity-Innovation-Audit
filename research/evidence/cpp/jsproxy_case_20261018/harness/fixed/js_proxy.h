/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_FRAMEWORKS_COMMON_JS_PROXY_H
#define OHOS_DISTRIBUTED_DATA_FRAMEWORKS_COMMON_JS_PROXY_H
#include <memory>
#include <mutex>
namespace OHOS::JSProxy {
template<typename T>
class JSCreator {
public:
    // This method will be used to call different subclasses for implementation
    virtual std::shared_ptr<T> Create() = 0;

protected:
    // It is not allowed to directly use parent class objects for construction and destruction
    JSCreator() = default;
    ~JSCreator() = default;
};

template<typename T>
class JSProxy {
public:
    void SetInstance(std::shared_ptr<T> instance)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_ = std::move(instance);
    }

    std::shared_ptr<T> GetInstance() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return instance_;
    }

protected:
    // It is not allowed to directly use parent class objects for construction and destruction
    JSProxy() = default;
    ~JSProxy() = default;

private:
    mutable std::mutex mutex_;
    std::shared_ptr<T> instance_;
};

template<typename T, typename U = T>
class JSEntity : public JSCreator<U>, public JSProxy<T> {
protected:
    // It is not allowed to directly use parent class objects for construction and destruction
    JSEntity() = default;
    ~JSEntity() = default;
};
} // namespace OHOS::JSProxy
#endif // OHOS_DISTRIBUTED_DATA_FRAMEWORKS_COMMON_JS_PROXY_H
