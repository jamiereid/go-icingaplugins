prjroot := justfile_directory()
builddir := prjroot + "/bin"

# default recipe to display help
_default:
    @just --list

build-check_cisco_powersupplies:
  cd {{prjroot}}/cmd/check_cisco_powersupplies && go build -o {{builddir}}/check_cisco_powersupplies

build-check_cisco_powerstack:
  cd {{prjroot}}/cmd/check_cisco_powerstack && go build -o {{builddir}}/check_cisco_powerstack

build-check_cisco_stackmodules:
  cd {{prjroot}}/cmd/check_cisco_stackmodules && go build -o {{builddir}}/check_cisco_stackmodules

build-all: clean-build build-check_cisco_powersupplies build-check_cisco_stackmodules build-check_cisco_powerstack

# clean out the build directory
clean-build:
  rm -rf {{builddir}}/*
