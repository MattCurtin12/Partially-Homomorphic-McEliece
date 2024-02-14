# [Generic Homomorphic Encryption and Its Application to Code-Based Cryptosystems (Draft)](https://github.com/MattCurtin12/Partially-Homomorphic-McEliece/blob/master/cm22geneic-draft.pdf)

# Authors
* Kirill Morozov
* Matt Curtin

# About
An implementation with testing for a partially homomorphic encryption scheme using the McEliece cryptosystem and its dual Niederreiter. 

The implementation for the Niederreiter scheme is from the NIST submission.

# How to build

## Requirements
### Linux OS
I used the Windows WSL2 feature with Ubuntu 22.04.3. 

You can find how to enable WSL2 on windows [here](https://www.freecodecamp.org/news/how-to-install-wsl2-windows-subsystem-for-linux-2-on-windows-10/)

### make
If you do not have make installed you can run the following command:
```
sudo apt-get install make
```

### gcc
To get gcc to run on the WSL2 environment, I ran the following commands from this [stack over flow post](https://stackoverflow.com/questions/62215963/how-to-install-gcc-and-gdb-for-wslwindows-subsytem-for-linux):
```
sudo apt-get update
sudo apt-get upgrade -y
sudo apt autoremove -y
sudo apt-get install gcc -y
```

### openssl
The NIST submission uses the openssl library. The dev version needs to be installed. 
```
sudo apt-get install libssl-dev
```

### Keccak
The NIST submission uses the Keccak SHAKE256 function. I used the [eXtended Keccak Code Package](https://github.com/XKCP/XKCP/tree/master) for the implementation. 

The library may need to be rebuilt depending on the machine. I have a provided a package file and headers in the keccak folder. To update this for you machine, follow these steps:

1. Clone the [XKCP repository](https://github.com/XKCP/XKCP/tree/master)
2. Edit Makefile.Build
3. Add ```<target name="libkeccak.a" inherits="FIPS202 K1600-compact"/>``` as shown below:
    ```
    <!-- To make a library -->
    <fragment name="libXKCP.a" inherits="All"/>
    <fragment name="libXKCP.so" inherits="All"/>

    <target name="libkeccak.a" inherits="FIPS202 K1600-compact"/>
    ```
4. Build the library
    ```
    make libkeccak.a
    ```
5. This will build the library in the bin folder. Copy the contents of the bin folder and paste them in this project's keccak folder.

## Build and Run
There are two folders for the compact and noncompact versions of the homomorphic scheme. 

### Compact example
To run the example encryption, computation, and decryption using the compact scheme, use ```make``` after navigating to the "compact" folder. 

The example begins with two messages, m1 and m2. The values of which are 6 (110 binary) and 5 (101 binary) respectively. The example shows the output for each step of the compact scheme. The messages are encoded, added using exclusive or, and then decrypted. 

At the end we get the final result of 3 (011 binary), which is correct.

### Compact timing
To get an average idea of timing for this scheme, use ```make time```

100 test cases will run and compute average times for each stage of the scheme. 

### Non Compact
The example and timing are run in the same file for the non compact scheme. 

The example is the same as with compact. Two messages are encrypted, added using exclusive or, and the result is decrypted. The expected result of c' = 3 is correct. 

Timing for this scheme is measured with a running total. 50 random messages are generated. They are encrypted, and added to a running total. The time for each operation is calculated. 

