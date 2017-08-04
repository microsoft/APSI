#include "Tools/clp.h"
#include <sstream>
#include <stdexcept>

using namespace std;

namespace apsi
{
	namespace tools
	{
		CLP::CLP(int argc, char *argv[])
		{
			parse(argc, argv);
		}

		void CLP::parse(int argc, char *argv[])
		{
			if (argc > 0)
			{
				stringstream ss;
				while (*argv[0] != 0)
				{
					ss << *argv[0]++;
				}
				program_name = ss.str();
			}

			for (int i = 1; i < argc;)
			{
				if (*argv[i]++ != '-')
				{
					throw CommandLineParserError("invalid argument");
				}

				stringstream ss;
				while (*argv[i] != 0)
				{
					ss << *argv[i]++;
				}

				++i;

				pair<string, list<string> > new_kv_pair;
				new_kv_pair.first = ss.str();

				while (i < argc && argv[i][0] != '-')
				{
					ss.str("");
					while (*argv[i] != 0)
					{
						ss << *argv[i]++;
					}

					new_kv_pair.second.push_back(ss.str());
					++i;
				}

				key_values.emplace(new_kv_pair);
			}
		}

		void CLP::set_default(string key, string value)
		{
			if (!has_value(key))
			{
				key_values.emplace(make_pair(key, list<string>{ value }));
			}
		}

		void CLP::set_default(vector<string> keys, string value)
		{
			if (!has_value(keys))
			{
				set_default(keys[0], value);
			}
		}

		bool CLP::is_set(string key)
		{
			return key_values.find(key) != key_values.end();
		}

		bool CLP::is_set(vector<string> keys)
		{
			for (auto key : keys)
			{
				if (is_set(key))
				{
					return true;
				}
			}
			return false;
		}

		bool CLP::has_value(string key)
		{
			return (key_values.find(key) != key_values.end()) && key_values[key].size();
		}

		bool CLP::has_value(vector<string> keys)
		{
			for (auto key : keys)
			{
				if (has_value(key))
				{
					return true;
				}
			}
			return false;
		}

		int CLP::get_int(string key)
		{
			if (!has_value(key))
			{
				throw CommandLineParserError("key has no associated value");
			}
			try
			{
				return stoi(*key_values[key].begin());
			}
			catch (const exception &e)
			{
				throw CommandLineParserError(e.what());
			}
		}

		int CLP::get_int(vector<string> keys, string fail_message)
		{
			for (auto key : keys)
			{
				if (has_value(key))
				{
					try
					{
						return stoi(*key_values[key].begin());
					}
					catch (const exception &e)
					{
						throw CommandLineParserError(e.what());
					}
				}
			}
			throw CommandLineParserError(fail_message);
		}

		string CLP::get_string(string key)
		{
			if (!has_value(key))
			{
				throw CommandLineParserError("key has no associated value");
			}
			return *key_values[key].begin();
		}

		list<string> CLP::get_strings(string key)
		{
			if (!is_set(key))
			{
				throw CommandLineParserError("key not found");
			}
			return key_values[key];
		}

		list<string> CLP::get_strings(vector<string> keys, string fail_message)
		{
			for (auto key : keys)
			{
				if (has_value(key))
				{
					return get_strings(key);
				}
			}
			throw CommandLineParserError(fail_message);
		}

		string CLP::get_string(vector<string> keys, string fail_message)
		{
			for (auto key : keys)
			{
				if (has_value(key))
				{
					return get_string(key);
				}
			}
			throw CommandLineParserError(fail_message);
		}
	}
}