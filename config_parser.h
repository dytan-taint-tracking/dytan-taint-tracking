#ifndef _CONFIG_PARSER_H
#define _CONFIG_PARSER_H

#include <string>
#include <vector>

struct source {
    // Type of taint source : legal values = path, network
    string type;
    // Granularity for the tainting : legal values = PerRead or PerByte
    string granularity;
    // actual details regarding taint source, like the filepath for a
    // path source and the host ip and port for a network source
    vector<string> details;
};

struct propagation {
    bool dataflow;
    bool controlflow;
};

struct location {
    string type;
    vector<string> actual_location;
};

struct sink {
    string id;
    location loc;
    string action;
};

struct profiling {
	bool marks;
	bool markop;
};

struct config {
    vector<source> sources;
    string num_markings;
    propagation prop;
    vector<sink> sinks;
    profiling prof;
};

int parseConfig(int , char **, config *);

#endif
