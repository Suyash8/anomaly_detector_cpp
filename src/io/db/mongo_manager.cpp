#include "mongo_manager.hpp"

#include <exception>
#include <iostream>
#include <memory>
#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>

mongocxx::instance MongoManager::instance_{};

MongoManager::MongoManager(const std::string &uri) {
  try {
    mongocxx::uri mongo_uri(uri);
    pool_ = std::make_unique<mongocxx::pool>(mongo_uri);
    std::cout << "MongoDB connection pool initialized for URI: " << uri
              << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "FATAL: Could not initialize MongoDB connection pool. Error: "
              << e.what() << std::endl;
    // This should probably terminate the program
    pool_ = nullptr;
  }
}

mongocxx::pool::entry MongoManager::get_client() {
  if (!pool_)
    throw std::runtime_error("MongoDB pool is not initialized.");
  return pool_->acquire();
}