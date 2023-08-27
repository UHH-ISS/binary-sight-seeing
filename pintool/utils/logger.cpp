#include "logger.h"

Logger *global_text_logger;
Logger *global_binary_logger;
Logger *global_ins_logger;
PIN_MUTEX trace_mutex;

Logger::~Logger() {}

FileLogger::FileLogger(std::string path) {
    out_ = new std::ofstream(path.c_str());
    PIN_MutexInit(&mutex_);
    unflushed_lines = 0;
}

FileLogger::~FileLogger() {
    out_->close();
    delete out_;
    PIN_MutexFini(&mutex_);
}

void FileLogger::lock() {
    PIN_MutexLock(&mutex_);
}

void FileLogger::unlock() {
    PIN_MutexUnlock(&mutex_);
}

void FileLogger::safe_log(const std::string &val) {
    lock();
    log(val);
    unlock();
}

void FileLogger::log(const std::string &val) {
    *out_ << val;
    out_->flush();
    unflushed_lines = 0;
}

void FileLogger::lazy_log(const std::string& val)
{
    *out_ << val;
    unflushed_lines += 1;

    if (unflushed_lines >= 100) {
        out_->flush();
        unflushed_lines = 0;
    }
}
