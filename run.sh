cd debugger_client_output

input_params="../debugger_server_output/debugger $1"
./gradlew run --console=plain --args="$input_params"

cd ..
