#pragma once

#include <unordered_map>
#include <list>
#include <vector>
#include <string>
#include <iostream>

namespace apsi
{
	namespace tools
	{
		class CommandLineParserError : public std::exception
		{
		public:
			CommandLineParserError() = default;

			CommandLineParserError(std::string message) : message_(message)
			{
				std::cerr << message;
			}

			virtual const char* what() const override
			{
				return message_.c_str();
			}

		private:
			const std::string message_;
		};

		class CLP
		{
		public:
			CLP() = default;
			CLP(int argc, char *argv[]);

			void parse(int argc, char *argv[]);

			void set_default(std::string key, std::string value);
			void set_default(std::vector<std::string> keys, std::string value);

			bool is_set(std::string key);
			bool is_set(std::vector<std::string> keys);

			bool has_value(std::string key);
			bool has_value(std::vector<std::string> keys);

			int get_int(std::string key);
			int get_int(std::vector<std::string> keys, std::string fail_message = "");

			std::string get_string(std::string key);
			std::list<std::string> get_strings(std::string key);

			std::string get_string(std::vector<std::string> keys, std::string fail_message = "");
			std::list<std::string> get_strings(std::vector<std::string> keys, std::string failMessage = "");

		private:
			std::string program_name;
			std::unordered_map<std::string, std::list<std::string> > key_values;
		};
	}
}
