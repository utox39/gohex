# gohex

> [!NOTE]
> Compatible with Linux only

## Description

## Requirements

- [Capstone](https://www.capstone-engine.org/)
- [LIEF](https://lief.re/)

## Installation

```bash
# Clone the repo
$ git clone url/to/gohex

# cd to the path
$ cd path/to/gohex

# Create the build folder
$ mkdir build

# Compile
$ make

# Install
$ sudo make install
```

## Usage

### View the hexdump of a binary file

```bash
$ gohex hex ./foo
```

### Disassemble a binary file

```bash
$ gohex disassemble ./foo
```

## Contributing

If you would like to contribute to this project just create a pull request which I will try to review
as soon as possible.