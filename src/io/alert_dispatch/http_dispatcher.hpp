#ifndef HTTP_DISPATCHER_HPP
#define HTTP_DISPATCHER_HPP

#include "io/alert_dispatch/base_dispatcher.hpp"

#include <string>
#include <string_view>

class HttpDispatcher : public IAlertDispatcher {
public:
  explicit HttpDispatcher(const std::string &webhook_url);
  bool dispatch(const Alert &alert) override;
  const char *get_name() const override { return "HttpDispatcher"; }
  std::string get_dispatcher_type() const override { return "http"; }

private:
  std::string host_;
  std::string path_;
  bool is_https_;

  // Re-use the JSON formatting from FileDispatcher
  std::string format_alert_to_json(const Alert &alert_data) const;
  std::string escape_json_value(std::string_view input) const;
};

#endif // HTTP_DISPATCHER_HPP