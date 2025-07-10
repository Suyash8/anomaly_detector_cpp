#ifndef MONGO_MANAGER_HPP
#define MONGO_MANAGER_HPP

#include <memory>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>
#include <string>

class MongoManager {
public:
  explicit MongoManager(const std::string &uri);

  mongocxx::pool::entry get_client();
  bool ping();

private:
  static mongocxx::instance instance_;
  std::unique_ptr<mongocxx::pool> pool_;
};

#endif // MONGO_MANAGER_HPP