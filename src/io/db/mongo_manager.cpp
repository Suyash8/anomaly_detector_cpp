#include "mongo_manager.hpp"
#include "core/logger.hpp"

#include <bsoncxx/builder/basic/document.hpp>
#include <exception>
#include <memory>
#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>

mongocxx::instance MongoManager::instance_{};

MongoManager::MongoManager(const std::string &uri) {
  try {
    mongocxx::uri mongo_uri(uri);
    pool_ = std::make_unique<mongocxx::pool>(mongo_uri);
    LOG(LogLevel::INFO, LogComponent::IO_DATABASE,
        "MongoDB connection pool initialized for URI: " << uri);
  } catch (const std::exception &e) {
    LOG(LogLevel::FATAL, LogComponent::IO_DATABASE,
        "Could not initialize MongoDB connection pool. Error: " << e.what());
    // This should probably terminate the program
    pool_ = nullptr;
  }
}

mongocxx::pool::entry MongoManager::get_client() {
  if (!pool_) {
    LOG(LogLevel::ERROR, LogComponent::IO_DATABASE,
        "MongoDB pool is not initialized.");
    throw std::runtime_error("MongoDB pool is not initialized.");
  }
  return pool_->acquire();
}

bool MongoManager::ping() {
  if (!pool_) {
    LOG(LogLevel::ERROR, LogComponent::IO_DATABASE,
        "MongoDB pool is not initialized.");
    return false;
  }
  try {
    auto client = pool_->acquire();

    bsoncxx::builder::basic::document doc_builder{};
    doc_builder.append(bsoncxx::builder::basic::kvp("ping", 1));

    // The "ping" command is a lightweight way to check server status
    (*client)["admin"].run_command(doc_builder.view());

    LOG(LogLevel::TRACE, LogComponent::IO_DATABASE,
        "MongoDB server is reachable and responsive.");

    return true;
  } catch (const std::exception &e) {
    LOG(LogLevel::FATAL, LogComponent::IO_DATABASE,
        "MongoDB server is unreachable. Error: " << e.what());
    return false;
  }
}