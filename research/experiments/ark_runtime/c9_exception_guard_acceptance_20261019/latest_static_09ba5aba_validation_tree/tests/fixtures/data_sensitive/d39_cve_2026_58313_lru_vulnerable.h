/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef APP_DOMAIN_VERIFY_APP_DETAILS_LRU_H
#define APP_DOMAIN_VERIFY_APP_DETAILS_LRU_H

#include <string>
#include <unordered_map>
#include <list>
#include <mutex>
#include <memory>

namespace OHOS {
namespace AppDomainVerify {
template <typename K, typename V>
class LruCacheUtil {
public:
    LruCacheUtil<K, V>() = default;
    LruCacheUtil<K, V>(size_t maxCap):maxCap_(maxCap){};
    bool SetMaxCap(size_t cap);
    bool Get(const K& key, V& value);
    void Put(const K& key, const V& value);
    void Clear();
    bool IsEmpty();
private:
    std::atomic<size_t> maxCap_ = 10;
    std::list<std::pair<K, V>> cache_;
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> lruMap_;
};

template<typename K, typename V>
bool LruCacheUtil<K, V>::SetMaxCap(size_t cap)
{
    maxCap_ = cap;
};

template<typename K, typename V>
bool LruCacheUtil<K, V>::Get(const K& key, V& value)
{
    if (lruMap_.find(key) == lruMap_.end()) {
        return false;
    }
    value = lruMap_[key]->second;
    cache_.erase(lruMap_[key]);
    cache_.push_front({key, value});
    lruMap_[key] = cache_.begin();
    return true;
};

template<typename K, typename V>
void LruCacheUtil<K, V>::Put(const K& key, const V& value)
{
    auto iter = lruMap_.find(key);
    if (iter != lruMap_.end()) {
        V val = lruMap_[key]->second;
        cache_.erase(iter->second);
        cache_.push_front({key, val});
        lruMap_[key] = cache_.begin();
        return;
    }
    if (lruMap_.size() == maxCap_) {
        lruMap_.erase(cache_.back().first);
        cache_.pop_back();
    }
    cache_.push_front({key, value});
    lruMap_[key] = cache_.begin();
    return;
};

template<typename K, typename V>
void LruCacheUtil<K, V>::Clear()
{
    cache_.clear();
    lruMap_.clear();
};

template<typename K, typename V>
bool LruCacheUtil<K, V>::IsEmpty()
{
    return lruMap_.empty();
};
}
}

#endif