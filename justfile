prjroot := justfile_directory()
builddir := prjroot + "/bin"

# default recipe to display help
_default:
    @just --list

build-check_cisco_powersupplies:
  cd {{prjroot}}/cmd/check_cisco_powersupplies && go build -o {{builddir}}/check_cisco_powersupplies

build-all: clean-build build-check_cisco_powersupplies

# clean out the build directory
clean-build:
  rm -rf {{builddir}}/*
