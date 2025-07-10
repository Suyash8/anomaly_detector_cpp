#include "mongo_manager.hpp"

#include <bsoncxx/builder/basic/document.hpp>
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

bool MongoManager::ping() {
  if (!pool_)
    return false;
  try {
    auto client = pool_->acquire();

    bsoncxx::builder::basic::document doc_builder{};
    doc_builder.append(bsoncxx::builder::basic::kvp("ping", 1));

    // The "ping" command is a lightweight way to check server status
    (*client)["admin"].run_command(doc_builder.view());

    return true;
  } catch (const std::exception &e) {
    std::cerr << "FATAL: MongoDB server is unreachable. Error: " << e.what()
              << std::endl;
    return false;
  }
}