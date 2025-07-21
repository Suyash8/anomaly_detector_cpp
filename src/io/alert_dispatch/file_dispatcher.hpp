#ifndef FILE_DISPATCHER_HPP
#define FILE_DISPATCHER_HPP

#include "base_dispatcher.hpp"

#include <fstream>
#include <string>

class FileDispatcher : public IAlertDispatcher {
public:
  explicit FileDispatcher(const std::string &file_path);
  ~FileDispatcher() override;

  bool dispatch(const Alert &alert) override;
  const char *get_name() const override { return "FileDispatcher"; }
  std::string get_dispatcher_type() const override { return "file"; }

private:
  std::string alert_file_output_path_;
  std::ofstream alert_file_stream_;

  friend class HttpDispatcher;
};

#endif // FILE_DISPATCHER_HPP