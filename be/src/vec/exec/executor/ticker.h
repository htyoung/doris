// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once
#include <atomic>
#include <chrono>
#include <mutex>

namespace doris {
namespace vectorized {

class Ticker {
public:
    virtual ~Ticker() = default;

    /**
     * Returns the number of nanoseconds since a fixed reference point
     */
    virtual int64_t read() const = 0;

protected:
    Ticker() = default;
};

class SystemTicker : public Ticker {
public:
    int64_t read() const override {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
    }
};

} // namespace vectorized
} // namespace doris