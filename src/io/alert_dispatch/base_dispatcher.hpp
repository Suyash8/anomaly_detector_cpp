#ifndef BASE_DISPATCHER_HPP
#define BASE_DISPATCHER_HPP

#include "core/alert.hpp"
#include <string>

struct Alert;

class IAlertDispatcher {
public:
  virtual ~IAlertDispatcher() = default;
  virtual bool dispatch(const Alert &alert) = 0;
  virtual const char *get_name() const = 0;
  virtual std::string get_dispatcher_type() const = 0;
};

#endif // BASE_DISPATCHER_HPP