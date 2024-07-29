apt-get update

# Clang
apt-get install clang

# CMake
apt-get install cmake

# Git
apt-get install git

# Capstone
apt-get install libcapstone-dev
git clone https://github.com/capstone-engine/capstone.git
cd capstone
git checkout v5
./make.sh
./make.sh install
cd ..

# Build
cmake -S ./ -B debugger_server_output && cmake --build debugger_server_output/