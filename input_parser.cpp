#include "input_parser.hpp"
#include "anonymization.hpp"
#include <string>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <map>
#include <list>
#include <regex>

int 
read_configFile(std::string const& filename, user_credentials& input)
{
    std::string line;
    std::ifstream finput(filename);

    if(finput.is_open()) {
        while(getline(finput, line)) {
            if(process_userInput(line, input) < 0) return -1;
        }
        std::cout << ">> Configuration file has been processed..." << std::endl;
        return 0;
    } else {
        std::cerr << ">> Error opening configuration file..." << std::endl;
        return -1;
    }
}

/* ---
    Returns:
        1 on correct line;
        0 on non-critical error;
       -1 on critical error;
--- */
int 
process_userInput(std::string line, user_credentials& input)
{
    std::string keyword, value;

    std::stringstream iss(line);
    if(line.find(":") == std::string::npos) {
        std::cerr << ">> Syntactically incorret line. Skipping line..." << std::endl;
        return 0;
    }
    if(std::getline(iss, keyword, ':') && std::getline(iss, value)) {
        keyword.erase(std::remove(keyword.begin(), keyword.end(), ' '), keyword.end());
        value.erase(std::remove(value.begin(), value.end(), ' '), value.end());
        if(insert_userInput(keyword, value, input) < 0) return -1;
    } else {
        std::cerr << ">> Error parsing line. Skipping line..." << std::endl;
        return 0;
    }
    return 1;
}

/* ---
     Returns:
        1 on correct input;
        0 on non-critical error;
       -1 on critical error   
--- */
int
insert_userInput(std::string keyword, std::string value, user_credentials& input)
{
    if(keyword == TOPIC) {
        input.topic = value; return 1;
    } else if(keyword == USER) {
        input.user = value; return 1;
    } else if(keyword == PASSWORD) {
        input.pwd = value; return 1;
    } else if(keyword == GROUP_ID) {
        input.grp_id = value; return 1;
    } else if(keyword == BROKERS) {
        input.brokers = value; return 1;
    } else if(keyword == INTERFACE_NAME) {
        input.iface_name = value; return 1;
    } else if(keyword == DESTINATION_IP) {
        input.dst_ip = value; return 1;
    } else if(keyword == DESTINATION_PORT) {
        int tmpInt{std::stoi(value)};
        input.dst_port = tmpInt; return 1;
    } else if(keyword == ANONYMIZATION) {
        input.anonymization = value; return 1;
    } else {
        std::cerr << ">> Keyword does not match any valid credential field. Skipping Value..." << std::endl;
        return 0;
    }
}

void 
print_userInput(user_credentials& input)
{
    std::cout << "=======================================================" << std::endl;
    std::cout << ">> TOPIC: " << input.topic << std::endl;
    std::cout << ">> USER: " << input.user << std::endl;
    std::cout << ">> PASSWORD: " << "*********" << std::endl;
    std::cout << ">> GROUP ID: " << input.grp_id << std::endl;
    std::cout << ">> BROKERS: " << input.brokers << std::endl;
    std::cout << ">> INTERFACE NAME: " << input.iface_name << std::endl;
    std::cout << ">> DESTINATION IP: " << input.dst_ip << std::endl;
    std::cout << ">> DESTINATION PORT: " << input.dst_port << std::endl;
    std::cout << ">> ANONYMIZATION: " << input.anonymization << std::endl;
    std::cout << "=======================================================" << std::endl;
}
