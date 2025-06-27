#include "file_dispatcher.hpp"

#include <iostream>
#include <string>

FileDispatcher::FileDispatcher(const std::string &file_path)
    : alert_file_output_path_(file_path) {
  if (!alert_file_output_path_.empty()) {
    alert_file_stream_.open(alert_file_output_path_, std::ios::app);
    if (!alert_file_stream_.is_open())
      std::cerr << "Error: FileDispatcher could not open alert output file: "
                << alert_file_output_path_ << std::endl;
  }
}
