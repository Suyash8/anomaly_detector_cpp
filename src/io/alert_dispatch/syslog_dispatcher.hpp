#ifndef SYSLOG_DISPATCHER_HPP
#define SYSLOG_DISPATCHER_HPP

#include "base_dispatcher.hpp"

class SyslogDispatcher : public IAlertDispatcher {
public:
  SyslogDispatcher();
  ~SyslogDispatcher() override;

  bool dispatch(const Alert &alert) override;
  const char *get_name() const override { return "SyslogDispatcher"; }
  std::string get_dispatcher_type() const override { return "syslog"; }
};

#endif // SYSLOG_DISPATCHER_HPP