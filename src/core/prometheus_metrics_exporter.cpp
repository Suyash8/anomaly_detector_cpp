#include "prometheus_metrics_exporter.hpp"

#include <algorithm>
#include <iomanip>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace prometheus {

PrometheusMetricsExporter::PrometheusMetricsExporter(const Config &config)
    : config_(config), server_(std::make_unique<httplib::Server>()) {
  setup_http_handlers();
}

PrometheusMetricsExporter::~PrometheusMetricsExporter() { stop_server(); }

void PrometheusMetricsExporter::register_counter(
    const std::string &name, const std::string &help,
    const std::vector<std::string> &label_names) {
  validate_metric_name(name);
  validate_label_names(label_names);

  std::unique_lock<std::shared_mutex> lock(metrics_mutex_);

  if (counters_.find(name) != counters_.end()) {
    throw std::invalid_argument("Counter with name '" + name +
                                "' already exists");
  }

  auto counter = std::make_unique<CounterMetric>();
  counter->name = name;
  counter->help = help;
  counter->label_names = label_names;

  counters_[name] = std::move(counter);
}

void PrometheusMetricsExporter::register_gauge(
    const std::string &name, const std::string &help,
    const std::vector<std::string> &label_names) {
  validate_metric_name(name);
  validate_label_names(label_names);

  std::unique_lock<std::shared_mutex> lock(metrics_mutex_);

  if (gauges_.find(name) != gauges_.end()) {
    throw std::invalid_argument("Gauge with name '" + name +
                                "' already exists");
  }

  auto gauge = std::make_unique<GaugeMetric>();
  gauge->name = name;
  gauge->help = help;
  gauge->label_names = label_names;

  gauges_[name] = std::move(gauge);
}

void PrometheusMetricsExporter::register_histogram(
    const std::string &name, const std::string &help,
    const std::vector<double> &buckets,
    const std::vector<std::string> &label_names) {
  validate_metric_name(name);
  validate_label_names(label_names);

  std::unique_lock<std::shared_mutex> lock(metrics_mutex_);

  if (histograms_.find(name) != histograms_.end()) {
    throw std::invalid_argument("Histogram with name '" + name +
                                "' already exists");
  }

  auto histogram = std::make_unique<HistogramMetric>();
  histogram->name = name;
  histogram->help = help;
  histogram->label_names = label_names;
  histogram->bucket_bounds =
      buckets.empty() ? get_default_histogram_buckets() : buckets;

  // Ensure buckets are sorted and include +Inf
  std::sort(histogram->bucket_bounds.begin(), histogram->bucket_bounds.end());
  if (histogram->bucket_bounds.empty() ||
      histogram->bucket_bounds.back() !=
          std::numeric_limits<double>::infinity()) {
    histogram->bucket_bounds.push_back(std::numeric_limits<double>::infinity());
  }

  histograms_[name] = std::move(histogram);
}

void PrometheusMetricsExporter::increment_counter(
    const std::string &name, const std::map<std::string, std::string> &labels,
    double value) {
  if (value < 0) {
    throw std::invalid_argument("Counter increment value must be non-negative");
  }

  std::shared_lock<std::shared_mutex> lock(metrics_mutex_);

  auto it = counters_.find(name);
  if (it == counters_.end()) {
    throw std::invalid_argument("Counter '" + name + "' not found");
  }

  auto &counter = *it->second;
  std::unique_lock<std::shared_mutex> counter_lock(counter.mutex);

  // Validate labels match registered label names
  if (labels.size() != counter.label_names.size()) {
    throw std::invalid_argument("Label count mismatch for counter '" + name +
                                "'");
  }

  for (const auto &label_name : counter.label_names) {
    if (labels.find(label_name) == labels.end()) {
      throw std::invalid_argument("Missing label '" + label_name +
                                  "' for counter '" + name + "'");
    }
  }

  // Initialize counter value if it doesn't exist
  if (counter.values.find(labels) == counter.values.end()) {
    counter.values[labels].store(0.0);
  }

  // Atomic add for double using compare-and-swap
  auto& atomic_value = counter.values[labels];
  double expected = atomic_value.load();
  while (!atomic_value.compare_exchange_weak(expected, expected + value)) {
    // Loop until successful
  }
}

void PrometheusMetricsExporter::set_gauge(
    const std::string &name, double value,
    const std::map<std::string, std::string> &labels) {
  std::shared_lock<std::shared_mutex> lock(metrics_mutex_);

  auto it = gauges_.find(name);
  if (it == gauges_.end()) {
    throw std::invalid_argument("Gauge '" + name + "' not found");
  }

  auto &gauge = *it->second;
  std::unique_lock<std::shared_mutex> gauge_lock(gauge.mutex);

  // Validate labels match registered label names
  if (labels.size() != gauge.label_names.size()) {
    throw std::invalid_argument("Label count mismatch for gauge '" + name +
                                "'");
  }

  for (const auto &label_name : gauge.label_names) {
    if (labels.find(label_name) == labels.end()) {
      throw std::invalid_argument("Missing label '" + label_name +
                                  "' for gauge '" + name + "'");
    }
  }

  // Initialize gauge value if it doesn't exist
  if (gauge.values.find(labels) == gauge.values.end()) {
    gauge.values[labels].store(0.0);
  }

  gauge.values[labels].store(value);
}

void PrometheusMetricsExporter::observe_histogram(
    const std::string &name, double value,
    const std::map<std::string, std::string> &labels) {
  std::shared_lock<std::shared_mutex> lock(metrics_mutex_);

  auto it = histograms_.find(name);
  if (it == histograms_.end()) {
    throw std::invalid_argument("Histogram '" + name + "' not found");
  }

  auto &histogram = *it->second;
  std::unique_lock<std::shared_mutex> histogram_lock(histogram.mutex);

  // Validate labels match registered label names
  if (labels.size() != histogram.label_names.size()) {
    throw std::invalid_argument("Label count mismatch for histogram '" + name +
                                "'");
  }

  for (const auto &label_name : histogram.label_names) {
    if (labels.find(label_name) == labels.end()) {
      throw std::invalid_argument("Missing label '" + label_name +
                                  "' for histogram '" + name + "'");
    }
  }

  // Initialize histogram series if it doesn't exist
  if (histogram.series.find(labels) == histogram.series.end()) {
    auto series = std::make_unique<HistogramMetric::HistogramSeries>();
    series->buckets.reserve(histogram.bucket_bounds.size());

    for (double bound : histogram.bucket_bounds) {
      series->buckets.push_back(std::make_unique<HistogramBucket>(bound));
    }

    histogram.series[labels] = std::move(series);
  }

  auto &series = *histogram.series[labels];

  // Update buckets
  for (auto &bucket : series.buckets) {
    if (value <= bucket->upper_bound) {
      bucket->count.fetch_add(1);
    }
  }

  // Update sum and count
  // Atomic add for double using compare-and-swap
  double expected_sum = series.sum.load();
  while (!series.sum.compare_exchange_weak(expected_sum, expected_sum + value)) {
    // Loop until successful
  }
  series.count.fetch_add(1);
}

bool PrometheusMetricsExporter::start_server() {
  if (server_running_.load()) {
    return true;
  }

  server_thread_ = std::make_unique<std::thread>([this]() {
    server_running_.store(true);
    server_->listen(config_.host, config_.port);
    server_running_.store(false);
  });

  // Give the server a moment to start
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  return server_running_.load();
}

void PrometheusMetricsExporter::stop_server() {
  if (server_running_.load()) {
    server_->stop();
    server_running_.store(false);

    if (server_thread_ && server_thread_->joinable()) {
      server_thread_->join();
    }
  }
}

bool PrometheusMetricsExporter::is_running() const {
  return server_running_.load();
}

std::string PrometheusMetricsExporter::generate_metrics_output() const {
  std::ostringstream output;

  std::shared_lock<std::shared_mutex> lock(metrics_mutex_);

  // Export counters
  for (const auto &[name, counter] : counters_) {
    std::shared_lock<std::shared_mutex> counter_lock(counter->mutex);

    output << "# HELP " << name << " " << counter->help << "\n";
    output << "# TYPE " << name << " counter\n";

    for (const auto &[labels, value] : counter->values) {
      output << name << format_labels(labels) << " " << std::fixed
             << std::setprecision(6) << value.load() << "\n";
    }
  }

  // Export gauges
  for (const auto &[name, gauge] : gauges_) {
    std::shared_lock<std::shared_mutex> gauge_lock(gauge->mutex);

    output << "# HELP " << name << " " << gauge->help << "\n";
    output << "# TYPE " << name << " gauge\n";

    for (const auto &[labels, value] : gauge->values) {
      output << name << format_labels(labels) << " " << std::fixed
             << std::setprecision(6) << value.load() << "\n";
    }
  }

  // Export histograms
  for (const auto &[name, histogram] : histograms_) {
    std::shared_lock<std::shared_mutex> histogram_lock(histogram->mutex);

    output << "# HELP " << name << " " << histogram->help << "\n";
    output << "# TYPE " << name << " histogram\n";

    for (const auto &[labels, series] : histogram->series) {
      // Export buckets
      for (const auto &bucket : series->buckets) {
        auto bucket_labels = labels;
        if (bucket->upper_bound == std::numeric_limits<double>::infinity()) {
          bucket_labels["le"] = "+Inf";
        } else {
          bucket_labels["le"] = std::to_string(bucket->upper_bound);
        }

        output << name << "_bucket" << format_labels(bucket_labels) << " "
               << bucket->count.load() << "\n";
      }

      // Export sum and count
      output << name << "_sum" << format_labels(labels) << " " << std::fixed
             << std::setprecision(6) << series->sum.load() << "\n";
      output << name << "_count" << format_labels(labels) << " "
             << series->count.load() << "\n";
    }
  }

  return output.str();
}

std::vector<double>
PrometheusMetricsExporter::get_default_histogram_buckets() const {
  return {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0};
}

std::string
PrometheusMetricsExporter::escape_label_value(const std::string &value) const {
  std::string escaped = value;

  // Escape backslashes first
  size_t pos = 0;
  while ((pos = escaped.find('\\', pos)) != std::string::npos) {
    escaped.replace(pos, 1, "\\\\");
    pos += 2;
  }

  // Escape quotes
  pos = 0;
  while ((pos = escaped.find('"', pos)) != std::string::npos) {
    escaped.replace(pos, 1, "\\\"");
    pos += 2;
  }

  // Escape newlines
  pos = 0;
  while ((pos = escaped.find('\n', pos)) != std::string::npos) {
    escaped.replace(pos, 1, "\\n");
    pos += 2;
  }

  return escaped;
}

std::string PrometheusMetricsExporter::format_labels(
    const std::map<std::string, std::string> &labels) const {
  if (labels.empty()) {
    return "";
  }

  std::ostringstream formatted;
  formatted << "{";

  bool first = true;
  for (const auto &[key, value] : labels) {
    if (!first) {
      formatted << ",";
    }
    formatted << key << "=\"" << escape_label_value(value) << "\"";
    first = false;
  }

  formatted << "}";
  return formatted.str();
}

void PrometheusMetricsExporter::validate_metric_name(
    const std::string &name) const {
  if (name.empty()) {
    throw std::invalid_argument("Metric name cannot be empty");
  }

  // Prometheus metric names must match [a-zA-Z_:][a-zA-Z0-9_:]*
  std::regex name_regex("^[a-zA-Z_:][a-zA-Z0-9_:]*$");
  if (!std::regex_match(name, name_regex)) {
    throw std::invalid_argument("Invalid metric name: " + name);
  }
}

void PrometheusMetricsExporter::validate_label_names(
    const std::vector<std::string> &label_names) const {
  std::regex label_regex("^[a-zA-Z_][a-zA-Z0-9_]*$");

  for (const auto &label_name : label_names) {
    if (label_name.empty()) {
      throw std::invalid_argument("Label name cannot be empty");
    }

    if (!std::regex_match(label_name, label_regex)) {
      throw std::invalid_argument("Invalid label name: " + label_name);
    }

    // Reserved label names
    if (label_name.substr(0, 2) == "__") {
      throw std::invalid_argument("Label name cannot start with '__': " +
                                  label_name);
    }
  }
}

void PrometheusMetricsExporter::setup_http_handlers() {
  server_->Get(config_.metrics_path,
               [this](const httplib::Request &req, httplib::Response &res) {
                 handle_metrics_request(req, res);
               });

  server_->Get(config_.health_path,
               [this](const httplib::Request &req, httplib::Response &res) {
                 handle_health_request(req, res);
               });
}

void PrometheusMetricsExporter::handle_metrics_request(
    [[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
  try {
    std::string metrics = generate_metrics_output();
    res.set_content(metrics, "text/plain; version=0.0.4; charset=utf-8");
    res.status = 200;
  } catch (const std::exception &e) {
    res.set_content("Error generating metrics: " + std::string(e.what()),
                    "text/plain");
    res.status = 500;
  }
}

void PrometheusMetricsExporter::handle_health_request(
    [[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
  res.set_content("OK", "text/plain");
  res.status = 200;
}

} // namespace prometheus