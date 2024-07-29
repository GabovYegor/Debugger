apt-get update

# Kotlin
apt install default-jdk
snap install --classic kotlin

# Gradle
snap install gradle --classic

# Build
mkdir debugger_client_output && cd debugger_client_output
gradle init --type kotlin-application --dsl kotlin < ../debugger_client/gradle_input.txt
rm -r app/
cp ../debugger_client/build.gradle.kts ./
cp -r ../debugger_client/src ./
./gradlew build
cd ..
