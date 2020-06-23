#ifndef _CONVERT_H
#define _CONVERT_H

#include <stdexcept>
#include <sstream>

class BadConversion : public std::runtime_error {
    public:
        BadConversion(const std::string& s);
};

template<typename T>
 inline void convert(const std::string& s, T& x,
		bool failIfLeftoverChars = true) {
	std::istringstream i(s);
	char c;
	if (!(i >> x) || (failIfLeftoverChars && i.get(c)))
		throw BadConversion(s);
}

template<typename T>
 inline T convertTo(const std::string& s, bool failIfLeftoverChars = true) {
	T x;
	convert(s, x, failIfLeftoverChars);
	return x;
}

#endif
