#ifndef ONNX_MODEL_HPP
#define ONNX_MODEL_HPP

#include "models/base_model.hpp"
#include <onnxruntime_cxx_api.h>
#include <string>
#include <vector>

class ONNXModel : public IAnomalyModel {
public:
  // Constructor now also takes the metadata path
  explicit ONNXModel(const std::string &model_path,
                     const std::string &metadata_path);
  ~ONNXModel() override;

  std::pair<double, std::vector<std::string>>
  score_with_explanation(const std::vector<double> &features) override;
  bool is_ready() const { return ready_; }

private:
  bool ready_ = false;

  // ONNX Runtime objects
  Ort::Env env_;
  Ort::Session session_;
  Ort::AllocatorWithDefaultOptions allocator_;

  // Model metadata
  std::vector<const char *> input_node_names_;
  std::vector<const char *> output_node_names_;
  std::vector<int64_t> input_node_dims_;
  std::vector<std::string> feature_names_;

  // Helper to convert C-style string arrays from ONNX API to something more
  // manageable
  std::vector<std::string> owned_input_names_;
  std::vector<std::string> owned_output_names_;

  void load_metadata(const std::string &metadata_path);
};

#endif // ONNX_MODEL_HPP