#ifndef SEASONAL_MODEL_HPP
#define SEASONAL_MODEL_HPP

#include <chrono>
#include <map>

class SeasonalModel {
public:
  enum class TimeContext { HOURLY, DAILY, WEEKLY };
  struct Baseline {
    double mean;
    double stddev;
    double confidence;
    size_t count;
    Baseline() : mean(0), stddev(0), confidence(0), count(0) {}
  };

  SeasonalModel(double sensitivity = 0.1, double learning_rate = 0.05);
  void add_observation(double value, std::chrono::system_clock::time_point ts);
  Baseline get_baseline(std::chrono::system_clock::time_point ts,
                        TimeContext ctx) const;
  double get_threshold(std::chrono::system_clock::time_point ts,
                       TimeContext ctx) const;
  double get_confidence(std::chrono::system_clock::time_point ts,
                        TimeContext ctx) const;
  void set_sensitivity(double sensitivity);
  void set_learning_rate(double rate);

private:
  double sensitivity_;
  double learning_rate_;
  std::map<int, Baseline> hourly_baselines_;
  std::map<int, Baseline> daily_baselines_;
  std::map<int, Baseline> weekly_baselines_;
  void update_baseline(Baseline &baseline, double value);
  int get_hour_key(std::chrono::system_clock::time_point ts) const;
  int get_day_key(std::chrono::system_clock::time_point ts) const;
  int get_week_key(std::chrono::system_clock::time_point ts) const;
};

#endif // SEASONAL_MODEL_HPP