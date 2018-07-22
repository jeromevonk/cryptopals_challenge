# cryptopals_challenge
My solution in C++ to the [cryptopals crypto challenge](https://cryptopals.com/).
Cross-platform solution, can be build in Windows (Visual Studio 2015) or Linux.
Find the solution file and/or the makefile in the 'workspace' folder.

Current stage:
- [x] Set 1
- [x] Set 2
- [ ] Set 3 - work in progress



## Windows

Build it with Visual Studio 2015 or newer.

## Linux

##### install latest openssl headers

`sudo apt-get install libssl-dev`

##### build

`cd workspace`
`make`

##### run

`./run_all_challenges.sh`
OR
`./run_set_1.sh`
`./run_set_2.sh`
`./run_set_3.sh`