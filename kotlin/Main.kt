import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter

fun main(args: Array<String>): Unit = runBlocking {
    println("Command-line arguments:")
    for (arg in args) {
        println(arg)
    }

    if(args.size != 2) {
        println("Usage: [/path/to/debugger] [/path/to/executable/to/debug]")
    }

    val exe = args[0]
    val params = args[1]
    val processBuilder = ProcessBuilder(exe, params)
    val process = processBuilder.start()

    val reader = BufferedReader(InputStreamReader(process.inputStream))
    val writer = OutputStreamWriter(process.outputStream)

    val channel = Channel<Unit>()
    val readJob = launch(Dispatchers.IO) {
        while (isActive) {
            if(!reader.ready()) {
                channel.send(Unit)
            }

            val line = reader.readLine()
            if (line != null) {
                println(line)
            }
        }
    }

    val writeJob = launch(Dispatchers.IO) {
        while (isActive) {
            // Wait while all process's data will be printed
            channel.receive()
            print("Input next command: ")
            val userInput = readLine()

            if(!process.isAlive)
            {
                break;
            }

            if (userInput != null) {
                writer.write(userInput + "\n")
                writer.flush()
            }
        }
    }

    process.waitFor()

    println("Debugged process finished! Press 'Enter' to finish")
    readJob.cancelAndJoin()
    writeJob.cancelAndJoin()
}
