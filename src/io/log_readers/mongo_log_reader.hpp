#ifndef MONGO_LOG_READER_HPP
#define MONGO_LOG_READER_HPP

#include "base_log_reader.hpp"
#include "core/config.hpp"
#include "io/db/mongo_manager.hpp"

#include <bsoncxx/document/view.hpp>
#include <cstdint>

class MongoLogReader : public ILogReader {
public:
  MongoLogReader(std::shared_ptr<MongoManager> manager,
                 const Config::MongoLogSourceConfig &config,
                 const std::string &reader_state_path);

  ~MongoLogReader() override;

  std::vector<LogEntry> get_next_batch() override;

private:
  void load_state();
  void save_state() const;
  LogEntry bson_to_log_entry(const bsoncxx::document::view &doc);

  std::shared_ptr<MongoManager> mongo_manager_;
  const Config::MongoLogSourceConfig &config_;
  std::string reader_state_path_;

  uint64_t last_processed_timestamp_ms_ = 0;
  static constexpr size_t BATCH_SIZE = 1000;
};

#endif // MONGO_LOG_READER_HPP