#include "syslog_dispatcher.hpp"
#include "core/alert.hpp"
#include "core/alert_manager.hpp"
#include "core/logger.hpp"

#include <sstream>
#include <syslog.h>

SyslogDispatcher::SyslogDispatcher() {
  openlog("anomaly_detector", LOG_PID | LOG_CONS, LOG_USER);
}

SyslogDispatcher::~SyslogDispatcher() { closelog(); }

bool SyslogDispatcher::dispatch(const Alert &alert) {
  try {
    std::ostringstream ss;
    ss << "ALERT: " << alert.alert_reason << " | "
       << "IP: " << alert.source_ip << " | "
       << "Tier: " << alert_tier_to_string_representation(alert.detection_tier)
       << " | "
       << "Score: " << alert.normalized_score;

    LOG(LogLevel::TRACE, LogComponent::IO_DISPATCH,
        "Dispatching alert to syslog: " << ss.str());
    // LOG_WARNING is a standard syslog level
    syslog(LOG_WARNING, "%s", ss.str().c_str());
    return true;
  } catch (const std::exception& e) {
    LOG(LogLevel::ERROR, LogComponent::IO_DISPATCH,
        "Exception while dispatching alert to syslog: " << e.what());
    return false;
  }
}