#include "models/onnx_model.hpp"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ONNXModel::ONNXModel(const std::string &model_path,
                     const std::string &metadata_path) try
    : env_(ORT_LOGGING_LEVEL_WARNING, "anomaly-detector-onnx"),
      session_(env_, model_path.c_str(), Ort::SessionOptions{nullptr}) {

  // Get input node details
  size_t num_input_nodes = session_.GetInputCount();
  if (num_input_nodes != 1)
    throw std::runtime_error("Model must have exactly one input node.");

  // Use GetInputNameAllocated which returns a smart pointer that manages memory
  owned_input_names_.push_back(
      session_.GetInputNameAllocated(0, allocator_).get());
  input_node_names_.push_back(owned_input_names_.back().c_str());

  Ort::TypeInfo type_info = session_.GetInputTypeInfo(0);
  auto tensor_info = type_info.GetTensorTypeAndShapeInfo();
  input_node_dims_ = tensor_info.GetShape();
  if (input_node_dims_.size() != 2 || input_node_dims_[0] != -1)
    throw std::runtime_error(
        "Model input must be a 2D tensor of shape [None, num_features].");

  // Get output node details
  size_t num_output_nodes = session_.GetOutputCount();
  owned_output_names_.reserve(num_output_nodes);
  output_node_names_.reserve(num_output_nodes);
  for (size_t i = 0; i < num_output_nodes; i++) {
    owned_output_names_.push_back(
        session_.GetOutputNameAllocated(i, allocator_).get());
    output_node_names_.push_back(owned_output_names_.back().c_str());
  }

  // Load metadata and validate feature count
  load_metadata(metadata_path);
  if (feature_names_.size() != static_cast<size_t>(input_node_dims_[1])) {
    throw std::runtime_error("Feature count in metadata (" +
                             std::to_string(feature_names_.size()) +
                             ") does not match model's expected input shape (" +
                             std::to_string(input_node_dims_[1]) + ").");
  }

  ready_ = true;
  std::cout << "ONNX model loaded successfully from: " << model_path
            << std::endl;

} catch (const Ort::Exception &e) {
  std::cerr << "Error loading ONNX model: " << e.what() << std::endl;
} catch (const std::exception &e) {
  std::cerr << "Standard Exception while loading ONNX model: " << e.what()
            << std::endl;
}

ONNXModel::~ONNXModel() = default;

void ONNXModel::load_metadata(const std::string &metadata_path) {
  std::ifstream f(metadata_path);
  if (!f.is_open())
    throw std::runtime_error("Could not open model metadata file: " +
                             metadata_path);

  json data = json::parse(f);
  feature_names_ =
      data["feature_names_ordered"].get<std::vector<std::string>>();
}

std::pair<double, std::vector<std::string>>
ONNXModel::score_with_explanation(const std::vector<double> &features) {
  if (!ready_ || (features.size() != static_cast<size_t>(input_node_dims_[1])))
    return {0.0, {"Model not ready or feature vector size mismatch"}};

  std::vector<float> float_features(features.begin(), features.end());

  Ort::MemoryInfo memory_info =
      Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
  Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
      memory_info, float_features.data(), float_features.size(),
      input_node_dims_.data(), input_node_dims_.size());

  auto output_tensors = session_.Run(
      Ort::RunOptions{nullptr}, input_node_names_.data(), &input_tensor, 1,
      output_node_names_.data(), output_node_names_.size());

  const float *score_data = output_tensors[1].GetTensorData<float>();
  double raw_score = static_cast<double>(score_data[0]);
  double normalized_score = 0.5 - raw_score;

  // For now, return a generic explanation inside a vector.
  std::vector<std::string> explanation = {"High ML Anomaly Score"};

  return {normalized_score, explanation};
}