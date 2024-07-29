# Install dependencies
apt-get update

# 1. Capstone
git clone https://github.com/capstone-engine/capstone.git
cd capstone
git checkout v5
./make.sh
./make.sh install
cd ..

# 2. Kotlin
apt install default-jdk
snap install --classic kotlin

# 3. Gradle
snap install gradle --classic

# 4. CMake
apt install cmake

cmake -S ./ -B debugger_output && cmake --build debugger_output/
mkdir debugger_client_output && cd debugger_client_output
gradle init --type kotlin-application --dsl kotlin < ../debugger_client/gradle_input.txt
rm -r app/
cp ../debugger_client/build.gradle.kts ./
cp -r ../debugger_client/src ./
./gradlew build
cd ..
