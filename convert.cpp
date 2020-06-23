#include "convert.h"

BadConversion::BadConversion(const std::string& s) :
		std::runtime_error(s) {
}
