# Introduction

Dytan is a dynamic taint analysis framework that allows users to implement different kinds of dynamic taint analyses. This file lists the system requirements of Dytan, illustrates how to install and run the tool, discusses the features of Dytan that can be accessed through the high-level XML interface, and finally presents the use of Dytan's core without leveraging the high-level XML interface.

# Requirements

Dytan is based on PIN and it is dependent on libxml2. It is capable of analyzing 32-bit binaries and the OS in which the tool was most recently tested is Ubuntu 14.04 32-bit.

# Install

To install Dytan perform the following steps:

* Download pin-2.14-67254-gcc.4.4.7-linux
	* `http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-gcc.4.4.7-linux.tar.gz`
* Open a terminal 
* Install xml2, libxml2-dev, and libxml2-utils package
	* `sudo apt-get install xml2`
	* `sudo apt-get install libxml2-dev`
	* `sudo apt-get install libxml2-utils`
* Move PIN tar file to the directory in which you would like to install it. Hereafter &lt;dir&gt; represents this directory
	* `mv pin-2.14-67254-gcc.4.4.7-linux.tar.gz <dir>;`
* Enter &lt;dir&gt; directory
	* `cd <dir>` 	
* Untar PIN
	*  `tar xpvzf pin-2.14-67254-gcc.4.4.7-linux.tar.gz`
* Move Dytan directory to PIN tools directory
	* `mv Dytan <dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools`
* Enter Dytan directory
	* `cd <dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan`
* Compile Dytan
	* `make`

# Run

The following list of steps presents how to run Dytan on the sample program released together with the tool distribution.

* Open a terminal
* Enter Dytan directory
	* `cd <dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan`
* Enter the sample program directory
	* `cd sample/wc`
* Compile the sample program
	* `make`
* Copy the Dytan configuration for the sample program into Dytan directory
	* `cp config.xml ../../config.xml`
* Enter Dytan directory
	* `cd ../..`
* Run Dytan on the sample program
	* `../../../pin -injection child -t obj-ia32/dytan.so -- sample/wc/wc sample/wc/a.txt sample/wc/b.txt`

# Configuration

## XML Configuration
Most of Dytan's options can be configured by using a configuration
file called `config.xml`. This file must be placed in `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan` directory. An example of configuration file is provided with the distribution within `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/sample/wc`directory. The configiguration file contains information about propagation policies, sources, and sinks.

The propagation policy is defined in the `<propagation>` section. By
specifying the `<controlflow>` tag as `false` or `true`, users can
define whether propagation should occur only through data dependences
or through both data and control dependences.

Taint sources are specified in the `<sources>` section. Within the
section, tag `<taint-marks>` is used to specify the number of unique
taint marks Dytan should use. For example, the following config
fragment would tell Dytan to use 32 unique taint marks:

	<sources>
		...
    	<taint-marks>32</taint-marks>
    	...
	</sources>

Currently, users can specify two kinds of taint sources in the config
file: files and network connections. To specify specific arguments of
a function or arbitrary memory ranges, users need to directly modify
the program or Dytan, respectively, as discussed in the following sections.

Files can be specified as sources in the config file as follows:

	<sources>
    	...
    	<source type="path">
        	<file>path/to/file1/filename1</file>
        	<file>path/to/file2/filename2</file>
        	<granularity>PerRead</granularity>
    	</source>
    	...
	</sources>

Note that, due to a current limitation of the implementation, Dytan
identifies file sources by matching the path used by the program with
the one specified in the `<source>` section. Therefore, the file path
specified in the config file should match what the program uses.

The `<granularity>` tag specifies the level of granularity at which
taint marks are assigned. Value `PerRead` tells Dytan to taint all the
bytes read by `read` operation with a single taint mark. Conversely,
value `PerByte` specifies that each byte read should be tainted with a
different taint mark. 

To taint data coming from a network connection, the user must add to
the config file a section in the following format:

	<sources>
    	...
    	<source type="network">
        	<host>127.0.0.1</host>
        	<port>80</port>
        	<granularity>PerRead</granularity>
    	</source>
    	...
	</sources>

There can be multiple `<source>` entries in the configuration file.


##Source Configuration
To taint arbitrary memory ranges from within your program, make a call
to function

	DYTAN_tag(ADDRINT start_address, size_t size, char * name)

where `size` is the size of the memory to be tainted and `name` is the
string to be associated with this taint mark.

Analogously, to display taint marks at a particular memory location
from within your program, make a call to function

	DYTAN_display(ADDRINT start_address, size_t size, char *fmt)

where `fmt` is the format in which the taint marks should be displayed.

The sample program provided with this distribution, available in
directory `sample/wc`, makes the above calls for tainting memory and
displaying memory taint marks.

#Internals

To get a better understanding of how Dytan operates, the best place to start is file `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/instrument_opcodes.cpp`. This file contains the modeling/propagation code for x86 instructions.

As an example, consider the propagation code for ADD in function
`Instrument_ADD`.  The comments around and in that function give a
code idea of how the propagation works and what needs to be done to
model additional instructions.

Currently, Dytan handles a subset of x86 instructions.  There are too
many instructions to make it worth while to implement code that
handles all of them, unless they are necessary. Therefore, we decided
to implement such code on demand, based on the instructions we found
in the subjects we analyzed. If Dytan encounters an instruction that
is not yet supported, it aborts and prints a message that indicates
the unhandled instruction in `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/out.log` file. To fix the issue, it is necessary to (1) add a function that handles the instruction in file `instrument_functions.cpp` and (2) add an entry to the dataflow dispatch table in file `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/dytan.cpp`.

We followed a similar on-demand approach in implementing the code that
models the effect of system calls. Also in this case, Dytan will print
a diagnostic message in `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/out.log` file and abort if it encounters a system call that it does not handle yet.  The procedure for fixing missing system calls is similar to the one for fixing missing instructions. The code for modeling system calls is located in file
`<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/syscall_functions.cpp`. When a new system call is added, an entry should also be added to the system call handler in file `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/dytan.cpp`.

One additional feature of Dytan is that it provides and API that can
be leveraged by client programs (see the program
`<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/sample/wc/wc.c` for a simple example).  There are a few caveats to keep in mind when using Dytan's API. First, to eliminate the need to link with Dytan during compilation, it is necessary to provide dummy implementations of the API functions used.  PIN is used to replace the
dummy implementations with Dytan's implementation at runtime. Second,
because the dummy implementations are usually empty, they get inlined
unless parameter `-O0` is specified as a compilation option for the
code under analysis. If the functions get inlined, PIN cannot replace
their implementation at runtime, which prevents them from being
executed.

Dytan's implementation of the API is in file `<dir>/pin-2.14-67254-gcc.4.4.7-linux/source/tools/Dytan/replace_functions.cpp`. 

Control-flow based taint propagation leverages post-dominance
information computed by one of Dytan's modules. In the presence of
indirect jumps in the code, postdominance information is not computed
and a special basic block is added in the position where the jump is.
To alleviate this issue, it is recommended to pre-process the source
code of the programs under analysis using CIL, whenever possible. CIL
eliminates some of the constructs that cause indirect jumps in the
code, such as "switch" statements.

# License

This software is released under the [GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/) license.