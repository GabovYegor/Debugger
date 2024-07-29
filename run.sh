cd debugger_client_output

input_str="../debugger_output/debugger $1"
./gradlew run --console=plain --args="$input_str"

cd ..
