#include "models/onnx_model.hpp"
#include "core/logger.hpp"
#include "core/metrics_manager.hpp"
#include "utils/scoped_timer.hpp"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ONNXModel::ONNXModel(const std::string &model_path,
                     const std::string &metadata_path) try
    : env_(ORT_LOGGING_LEVEL_WARNING, "anomaly-detector-onnx"),
      session_(env_, model_path.c_str(), Ort::SessionOptions{nullptr}) {

  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "Attempting to load ONNX model from: " << model_path);

  // Get input node details
  size_t num_input_nodes = session_.GetInputCount();
  if (num_input_nodes != 1)
    throw std::runtime_error("Model must have exactly one input node.");

  // Use GetInputNameAllocated which returns a smart pointer that manages memory
  owned_input_names_.push_back(
      session_.GetInputNameAllocated(0, allocator_).get());
  input_node_names_.push_back(owned_input_names_.back().c_str());
  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Model input node name: " << input_node_names_[0]);

  Ort::TypeInfo type_info = session_.GetInputTypeInfo(0);
  auto tensor_info = type_info.GetTensorTypeAndShapeInfo();
  input_node_dims_ = tensor_info.GetShape();
  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Model input dimensions: " << input_node_dims_.size());
  if (input_node_dims_.size() != 2 || input_node_dims_[0] != -1)
    throw std::runtime_error(
        "Model input must be a 2D tensor of shape [None, num_features].");

  // Get output node details
  size_t num_output_nodes = session_.GetOutputCount();
  owned_output_names_.reserve(num_output_nodes);
  output_node_names_.reserve(num_output_nodes);
  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Model has " << num_output_nodes << " output nodes.");
  for (size_t i = 0; i < num_output_nodes; i++) {
    owned_output_names_.push_back(
        session_.GetOutputNameAllocated(i, allocator_).get());
    output_node_names_.push_back(owned_output_names_.back().c_str());
    LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
        "Model output node " << i << " name: " << output_node_names_.back());
  }

  // Load metadata and validate feature count
  load_metadata(metadata_path);
  if (feature_names_.size() != static_cast<size_t>(input_node_dims_[1])) {
    throw std::runtime_error("Feature count in metadata (" +
                             std::to_string(feature_names_.size()) +
                             ") does not match model's expected input shape (" +
                             std::to_string(input_node_dims_[1]) + ").");
  }
  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Validated feature count against metadata: " << feature_names_.size()
                                                   << " features.");

  ready_ = true;
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "ONNX model loaded successfully.");

} catch (const Ort::Exception &e) {
  LOG(LogLevel::FATAL, LogComponent::ML_LIFECYCLE,
      "ONNX Runtime Exception while loading model: " << e.what());
} catch (const std::exception &e) {
  LOG(LogLevel::FATAL, LogComponent::ML_LIFECYCLE,
      "Standard Exception while loading ONNX model: " << e.what());
}

ONNXModel::~ONNXModel() = default;

void ONNXModel::load_metadata(const std::string &metadata_path) {
  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Loading model metadata from: " << metadata_path);
  std::ifstream f(metadata_path);
  if (!f.is_open())
    throw std::runtime_error("Could not open model metadata file: " +
                             metadata_path);

  json data = json::parse(f);
  feature_names_ =
      data["feature_names_ordered"].get<std::vector<std::string>>();
  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Loaded " << feature_names_.size() << " feature names from metadata.");
}

std::pair<double, std::vector<std::string>>
ONNXModel::score_with_explanation(const std::vector<double> &features) {
  static Histogram *inference_timer =
      MetricsManager::instance().register_histogram(
          "ad_ml_inference_duration_seconds",
          "Latency of a single ONNX model inference call.");

  LOG(LogLevel::TRACE, LogComponent::ML_INFERENCE,
      "Entering ONNXModel::score_with_explanation.");

  if (!ready_ ||
      (features.size() != static_cast<size_t>(input_node_dims_[1]))) {
    LOG(LogLevel::ERROR, LogComponent::ML_INFERENCE,
        "Scoring failed: Model not ready or feature vector size mismatch. "
        "Expected "
            << input_node_dims_[1] << ", got " << features.size());
    return {0.0, {"Model not ready or feature vector size mismatch"}};
  }

  // Convert double vector to float vector for ONNX Runtime
  std::vector<float> float_features(features.begin(), features.end());

  Ort::MemoryInfo memory_info =
      Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
  Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
      memory_info, float_features.data(), float_features.size(),
      input_node_dims_.data(), input_node_dims_.size());
  LOG(LogLevel::TRACE, LogComponent::ML_INFERENCE,
      "Created input tensor for ONNX Runtime.");

  // Instrument the Run() call
  std::vector<Ort::Value> output_tensors;

  {
    ScopedTimer timer(*inference_timer);
    output_tensors = session_.Run(
        Ort::RunOptions{nullptr}, input_node_names_.data(), &input_tensor, 1,
        output_node_names_.data(), output_node_names_.size());
  }

  LOG(LogLevel::TRACE, LogComponent::ML_INFERENCE,
      "ONNX session Run() completed.");

  // For IsolationForest from scikit-learn, output_tensors[0] are the labels (-1
  // or 1) and output_tensors[1] are the raw scores.
  const float *score_data = output_tensors[1].GetTensorData<float>();
  double raw_score = static_cast<double>(score_data[0]);

  // Scikit-learn's IsolationForest `score_samples` returns higher scores for
  // normal points and lower (more negative) scores for outliers. We normalize
  // this to a 0-1 range where 1.0 is a high-confidence anomaly. 0.5 is the
  // decision boundary.
  double normalized_score = 0.5 - raw_score;
  LOG(LogLevel::DEBUG, LogComponent::ML_INFERENCE,
      "ONNX model raw score: " << raw_score
                               << ", normalized score: " << normalized_score);

  // For now, return a generic explanation inside a vector.
  // The advanced explainability logic can be added here.
  std::vector<std::string> explanation = {"High ML Anomaly Score"};

  return {normalized_score, explanation};
}