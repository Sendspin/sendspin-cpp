// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file main.cpp
/// @brief Test entry point with an in-process hang watchdog. Tests wait on events with no
/// timeout, so a regression hangs; this aborts the run with the hung test's name and the main
/// thread's stack, which the CTest TIMEOUT alone cannot provide and a direct run has no other
/// guard for.

#include <execinfo.h>
#include <gtest/gtest.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>

namespace {

// Below the CTest TIMEOUT in tests/CMakeLists.txt so this fires first and CTest records the
// diagnostic; CTest remains the backstop if this thread cannot run.
constexpr auto WATCHDOG_BUDGET = std::chrono::seconds(55);

pthread_t main_thread;

// Signal handler run on the main thread, where every blocking test helper waits.
// backtrace_symbols_fd writes straight to the fd, so nothing here allocates.
void dump_stack(int /*signum*/) {
    void* frames[64];
    int count = backtrace(frames, 64);
    backtrace_symbols_fd(frames, count, STDERR_FILENO);
}

class HangWatchdog : public testing::EmptyTestEventListener {
public:
    HangWatchdog() : thread_([this] { this->run(); }) {}

    ~HangWatchdog() override {
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->stopping_ = true;
        }
        this->cv_.notify_all();
        this->thread_.join();
    }

    void OnTestStart(const testing::TestInfo& info) override {
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->current_ = &info;
            this->deadline_ = std::chrono::steady_clock::now() + WATCHDOG_BUDGET;
        }
        this->cv_.notify_all();
    }

    void OnTestEnd(const testing::TestInfo& /*info*/) override {
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->current_ = nullptr;
        }
        this->cv_.notify_all();
    }

private:
    void run() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        while (!this->stopping_) {
            if (this->current_ == nullptr) {
                this->cv_.wait(lock);
                continue;
            }
            if (this->cv_.wait_until(lock, this->deadline_) == std::cv_status::timeout &&
                this->current_ != nullptr) {
                this->fire(*this->current_);
            }
        }
    }

    static void fire(const testing::TestInfo& info) {
        std::fprintf(stderr, "\nHang watchdog: %s.%s (%s:%d) still running after %lld s\n",
                     info.test_suite_name(), info.name(), info.file() ? info.file() : "?",
                     info.line(), static_cast<long long>(WATCHDOG_BUDGET.count()));
        std::fflush(stderr);
        pthread_kill(main_thread, SIGUSR1);
        // Give the handler time to write the stack before the process goes down.
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::abort();
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    const testing::TestInfo* current_{nullptr};
    std::chrono::steady_clock::time_point deadline_;
    bool stopping_{false};
    std::thread thread_;
};

}  // namespace

int main(int argc, char** argv) {
    main_thread = pthread_self();
    struct sigaction action {};
    action.sa_handler = dump_stack;
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR1, &action, nullptr);
    // backtrace() may allocate on first use; take that hit here rather than in the handler.
    void* prime[1];
    backtrace(prime, 1);

    testing::InitGoogleTest(&argc, argv);
    testing::UnitTest::GetInstance()->listeners().Append(new HangWatchdog);  // gtest owns it
    return RUN_ALL_TESTS();
}
