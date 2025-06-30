#ifndef MODEL_DATA_COLLECTOR_HPP
#define MODEL_DATA_COLLECTOR_HPP

#include <fstream>
#include <mutex>
#include <string>
#include <vector>

class ModelDataCollector {
public:
  explicit ModelDataCollector(const std::string &output_path);
  ~ModelDataCollector();

  void collect_features(const std::vector<double> &features);

private:
  std::ofstream output_file_;
  std::mutex file_mutex_;
};

#endif // MODEL_DATA_COLLECTOR_HPP