#ifndef STUB_MODEL_HPP
#define STUB_MODEL_HPP

#include "base_model.hpp"

// A simple stub model for testing the pipeline before real models are
// integrated
class StubModel : public IAnomalyModel {
public:
  std::pair<double, std::vector<std::string>>
  score_with_explanation(const std::vector<double> &features) override;
};

#endif // STUB_MODEL_HPP