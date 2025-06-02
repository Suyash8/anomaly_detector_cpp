#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <array>
#include <algorithm>

const size_t TOTAL_LINES = 2'000'000;
const double MALFORMED_PERCENT = 0.02;

std::mt19937 rng(std::random_device{}());
std::uniform_real_distribution<> prob(0.0, 1.0);
std::uniform_int_distribution<> port_dist(1000, 9999);
std::uniform_int_distribution<> status_dist(0, 11);
std::uniform_int_distribution<> host_dist(0, 3);
std::uniform_int_distribution<> country_dist(0, 8);
std::uniform_int_distribution<> referer_dist(0, 4);
std::uniform_int_distribution<> request_dist(0, 3);
std::uniform_int_distribution<> encoding_dist(0, 4);
std::uniform_int_distribution<> malformed_type(0, 5);
std::uniform_int_distribution<> remove_fields(1, 5);

const std::array<std::string, 12> statuses = {"200", "201", "204", "301", "302", "400", "401", "403", "404", "500", "502", "503"};
const std::array<std::string, 5> referers = {"-", "https://google.com", "https://facebook.com", "https://bing.com", "https://reddit.com"};
const std::array<std::string, 4> hosts = {"example.com", "api.example.com", "site.test.org", "localhost"};
const std::array<std::string, 9> countries = {"US", "GB", "DE", "IN", "CN", "FR", "JP", "BR", "AU"};
const std::array<std::string, 4> requests = {"GET / HTTP/1.1", "POST /login HTTP/1.1", "GET /api/data HTTP/2.0", "DELETE /user/123 HTTP/1.1"};
const std::array<std::string, 5> encodings = {"gzip", "deflate", "br", "gzip, deflate, br", "*"};

std::string random_ip() {
    return std::to_string(rng() % 256) + "." + std::to_string(rng() % 256) + "." +
           std::to_string(rng() % 256) + "." + std::to_string(rng() % 256);
}

std::string random_username() {
    std::string name = "";
    int len = rng() % 6 + 5;
    for (int i = 0; i < len; ++i)
        name += static_cast<char>('a' + rng() % 26);
    return name;
}

std::string current_time_formatted() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm *gmt = std::gmtime(&t);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%d/%b/%Y:%H:%M:%S +0000", gmt);
    return buffer;
}

std::string random_uuid() {
    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        int byte = rng() % 256;
        oss << std::hex << std::setw(2) << std::setfill('0') << byte;
        if (i == 3 || i == 5 || i == 7 || i == 9)
            oss << "-";
    }
    return oss.str();
}

std::string random_float_str(double min, double max, int precision = 3) {
    std::ostringstream oss;
    std::uniform_real_distribution<> dist(min, max);
    oss << std::fixed << std::setprecision(precision) << dist(rng);
    return oss.str();
}

std::string generate_log_line() {
    std::string ip = random_ip();
    std::string user = (prob(rng) > 0.8) ? "-" : random_username();
    std::string time = current_time_formatted();
    std::string req_time = random_float_str(0.001, 5.0);
    std::string upstream_time = (prob(rng) > 0.1) ? random_float_str(0.001, 3.0) : "-";
    std::string req = requests[request_dist(rng)];
    std::string status = statuses[status_dist(rng)];
    std::string bytes = std::to_string(rng() % 5000 + 100);
    std::string referer = referers[referer_dist(rng)];
    std::string agent = "Mozilla/5.0";
    std::string host = hosts[host_dist(rng)];
    std::string country = countries[country_dist(rng)];
    std::string upstream_addr = random_ip() + ":" + std::to_string(port_dist(rng));
    std::string req_id = random_uuid();
    std::string encoding = encodings[encoding_dist(rng)];

    std::ostringstream oss;
    oss << ip << "|" << user << "|" << time << "|" << req_time << "|" << upstream_time << "|"
        << req << "|" << status << "|" << bytes << "|" << referer << "|" << agent << "|" << host << "|"
        << country << "|" << upstream_addr << "|" << req_id << "|" << encoding;
    return oss.str();
}

std::string generate_malformed_line() {
    int type = malformed_type(rng);
    std::string base = generate_log_line();
    std::vector<std::string> fields;
    std::istringstream ss(base);
    std::string token;
    while (std::getline(ss, token, '|'))
        fields.push_back(token);

    switch (type) {
        case 0: return "completely malformed garbage text";
        case 1: std::replace(base.begin(), base.end(), '|', ' '); return base;
        case 2: fields.resize(fields.size() - remove_fields(rng)); break;
        case 3: return base + "|extra_field";
        case 4: return std::string(15, '|');  // many empty fields
        case 5: return std::string("null|null|null|null|null|null|null|null|null|null|null|null|null|null|null");
    }

    std::ostringstream malformed;
    for (size_t i = 0; i < fields.size(); ++i) {
        malformed << fields[i];
        if (i != fields.size() - 1) malformed << "|";
    }
    return malformed.str();
}

int main() {
    std::ofstream file("./data/fake.log");

    for (size_t i = 1; i <= TOTAL_LINES; ++i) {
        if (prob(rng) < MALFORMED_PERCENT)
            file << generate_malformed_line();
        else
            file << generate_log_line();
        file << "\n";

        if (i % 100000 == 0)
            std::cout << "Written: " << i << " lines\n";
    }

    file.close();
    std::cout << "Log generation completed.\n";
    return 0;
}
