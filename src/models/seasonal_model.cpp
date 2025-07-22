#include "seasonal_model.hpp"

#include <cmath>
#include <stdexcept>

SeasonalModel::SeasonalModel(double sensitivity, double learning_rate)
    : sensitivity_(sensitivity), learning_rate_(learning_rate) {}

void SeasonalModel::add_observation(double value,
                                    std::chrono::system_clock::time_point ts) {
  int hour = get_hour_key(ts);
  int day = get_day_key(ts);
  int week = get_week_key(ts);
  update_baseline(hourly_baselines_[hour], value);
  update_baseline(daily_baselines_[day], value);
  update_baseline(weekly_baselines_[week], value);
}

SeasonalModel::Baseline
SeasonalModel::get_baseline(std::chrono::system_clock::time_point ts,
                            TimeContext ctx) const {
  int key;
  switch (ctx) {
  case TimeContext::HOURLY:
    key = get_hour_key(ts);
    return hourly_baselines_.at(key);
  case TimeContext::DAILY:
    key = get_day_key(ts);
    return daily_baselines_.at(key);
  case TimeContext::WEEKLY:
    key = get_week_key(ts);
    return weekly_baselines_.at(key);
  default:
    throw std::runtime_error("Invalid TimeContext");
  }
}

double SeasonalModel::get_threshold(std::chrono::system_clock::time_point ts,
                                    TimeContext ctx) const {
  Baseline b = get_baseline(ts, ctx);
  return b.mean + sensitivity_ * b.stddev;
}

double SeasonalModel::get_confidence(std::chrono::system_clock::time_point ts,
                                     TimeContext ctx) const {
  Baseline b = get_baseline(ts, ctx);
  return b.confidence;
}

void SeasonalModel::set_sensitivity(double sensitivity) {
  sensitivity_ = sensitivity;
}
void SeasonalModel::set_learning_rate(double rate) { learning_rate_ = rate; }

void SeasonalModel::update_baseline(Baseline &baseline, double value) {
  baseline.count++;
  double delta = value - baseline.mean;
  baseline.mean += learning_rate_ * delta;
  baseline.stddev =
      std::sqrt((1 - learning_rate_) * baseline.stddev * baseline.stddev +
                learning_rate_ * delta * delta);
  baseline.confidence = baseline.count > 10 ? 1.0 : baseline.count / 10.0;
}

int SeasonalModel::get_hour_key(
    std::chrono::system_clock::time_point ts) const {
  time_t t = std::chrono::system_clock::to_time_t(ts);
  struct tm buf;
  localtime_r(&t, &buf);
  return buf.tm_hour;
}
int SeasonalModel::get_day_key(std::chrono::system_clock::time_point ts) const {
  time_t t = std::chrono::system_clock::to_time_t(ts);
  struct tm buf;
  localtime_r(&t, &buf);
  return buf.tm_wday;
}
int SeasonalModel::get_week_key(
    std::chrono::system_clock::time_point ts) const {
  time_t t = std::chrono::system_clock::to_time_t(ts);
  struct tm buf;
  localtime_r(&t, &buf);
  return buf.tm_yday / 7;
}
