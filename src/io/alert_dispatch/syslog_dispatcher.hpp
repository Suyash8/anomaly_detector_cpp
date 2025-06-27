#ifndef SYSLOG_DISPATCHER_HPP
#define SYSLOG_DISPATCHER_HPP

#include "base_dispatcher.hpp"

class SyslogDispatcher : public IAlertDispatcher {
public:
  SyslogDispatcher();
  ~SyslogDispatcher() override;

  void dispatch(const Alert &alert) override;
  const char *get_name() const override { return "SyslogDispatcher"; }
};

#endif // SYSLOG_DISPATCHER_HPP