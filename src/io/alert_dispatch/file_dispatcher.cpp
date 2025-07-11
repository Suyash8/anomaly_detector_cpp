#include "file_dispatcher.hpp"
#include "utils/json_formatter.hpp"

#include <iostream>
#include <string>

FileDispatcher::FileDispatcher(const std::string &file_path)
    : alert_file_output_path_(file_path) {
  if (!alert_file_output_path_.empty()) {
    Utils::create_directory_for_file(alert_file_output_path_);
    alert_file_stream_.open(alert_file_output_path_, std::ios::app);
    if (!alert_file_stream_.is_open())
      std::cerr << "Error: FileDispatcher could not open alert output file: "
                << alert_file_output_path_ << std::endl;
  }
}

FileDispatcher::~FileDispatcher() {
  if (alert_file_stream_.is_open()) {
    alert_file_stream_.flush();
    alert_file_stream_.close();
  }
}

void FileDispatcher::dispatch(const Alert &alert) {
  if (alert_file_stream_.is_open()) {
    // Use the shared formatter to get the JSON string
    std::string json_output = JsonFormatter::format_alert_to_json(alert);
    alert_file_stream_ << json_output << std::endl; // endl also flushes
  }
}