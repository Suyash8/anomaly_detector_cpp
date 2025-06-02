#include "utils.hpp"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main() {
  std::cout << "Starting Anomaly Detection Engine..." << std::endl;

  uint64_t start = Utils::get_current_time_ms();

  // Trying to read the sample log file
  std::string log_filepath = "data/sample_logs.txt";
  std::ifstream log_file(log_filepath);

  if (!log_file.is_open()) {
    std::cerr << "Error: Could not open log file: " << log_filepath
              << std::endl;
    return 1;
  }

  std::cout << "Successfully opened log file: " << log_filepath << std::endl;

  std::string current_line;
  int line_counter = 0;

  //   Read and process a few lines
  while (std::getline(log_file, current_line)) {
    line_counter++;
    std::cout << "Read line " << line_counter << ": " << current_line
              << std::endl;

    // Try splitting the line
    std::vector<std::string> fields = Utils::split_string(current_line, '|');
    std::cout << "  Number of fields found: " << fields.size() << std::endl;

    if (fields.size() >= 1) {
      std::cout << "  IP Address (Field 1): " << fields[0] << std::endl;
    }

    if (line_counter > 5) {
      break;
    }
  }

  log_file.close();

  uint64_t stop = Utils::get_current_time_ms();
  std::cout << "Finished processing initial lines" << std::endl;
  std::cout << "Time taken: " << (stop - start) << " ms" << std::endl;

  return 0;
}