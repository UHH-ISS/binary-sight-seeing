#pragma once

#include <string>
#include <ostream>
#include <fstream>

#include "pin.H"

// A logger that can be used for logging in a
// multithreaded environment. When logging,
// a PIN_MUTEX is used for synchronization.

class Logger {
public:
    virtual ~Logger() = 0;

    Logger& get_global_logger();

    virtual void safe_log(const std::string &val) = 0;
    virtual void log(const std::string &val) = 0;
    virtual void lazy_log(const std::string& val) = 0;

    virtual void lock() = 0;
    virtual void unlock() = 0;
   
};

extern Logger *global_text_logger;
extern Logger *global_binary_logger;
extern Logger *global_ins_logger;
extern PIN_MUTEX trace_mutex;

class FileLogger : public Logger {
public:
    FileLogger(std::string path);
    ~FileLogger();

    void safe_log(const std::string &val);
    void log(const std::string &val);
    void lazy_log(const std::string& val);
    void lock();
    void unlock();

private:
    std::ofstream *out_;
    PIN_MUTEX mutex_;
    int unflushed_lines;
};

class NullLogger : public Logger {
public:
    NullLogger() {};
    ~NullLogger() {};

    void safe_log(const std::string& val) {};
    void log(const std::string& val) {};
    void lazy_log(const std::string& val) {};
    void lock() {};
    void unlock() {};
};