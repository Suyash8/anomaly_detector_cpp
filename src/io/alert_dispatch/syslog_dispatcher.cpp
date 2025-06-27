#include "syslog_dispatcher.hpp"

#include <sstream>
#include <syslog.h>

SyslogDispatcher::SyslogDispatcher() {
  openlog("anomaly_detector", LOG_PID | LOG_CONS, LOG_USER);
}

SyslogDispatcher::~SyslogDispatcher() { closelog(); }

void SyslogDispatcher::dispatch(const Alert &alert) {
  std::ostringstream ss;
  ss << "ALERT: " << alert.alert_reason << " | "
     << "IP: " << alert.source_ip << " | "
     << "Tier: " << alert_tier_to_string_representation(alert.detection_tier)
     << " | "
     << "Score: " << alert.normalized_score;

  // LOG_WARNING is a standard syslog level
  syslog(LOG_WARNING, "%s", ss.str().c_str());
}