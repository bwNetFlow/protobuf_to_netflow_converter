#ifndef INPUT_PARSER_HPP
#define INPUT_PARSER_HPP

#include <iostream>
#include <fstream>

#include "structs.hpp"

int read_configFile(std::string const& filename, user_credentials& input);

int process_userInput(std::string line, user_credentials& input);

int insert_userInput(std::string keyword, std::string value, user_credentials& input);

void print_userInput(user_credentials& input);

#endif
