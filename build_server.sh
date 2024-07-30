apt-get update

# Clang
apt-get install clang

# CMake
apt-get install cmake

# Git
apt-get install git

if find /usr/local/lib /usr/lib -name "libcapstone.so"; then
    echo "libcapstone already installed. Please make sure you're using the latest version!"
else
  # Capstone
  git clone https://github.com/capstone-engine/capstone.git
  cd capstone
  git checkout v5
  ./make.sh
  ./make.sh install
  cd ..
  rm -r capstone
fi

# Build
cd debugger_server
cmake -S ./ -B debugger_server_output && cmake --build debugger_server_output/
cd ..