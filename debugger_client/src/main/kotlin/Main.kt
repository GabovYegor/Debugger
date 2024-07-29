import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import kotlin.system.exitProcess

fun main(args: Array<String>): Unit = runBlocking {
    if(args.size != 2) {
        println("Wrong command line params. Usage: [/path/to/debugger] [/path/to/executable/to/debug]")
        exitProcess(0)
    }

    val debugger = args[0]
    val process_to_debug = args[1]

    val processBuilder = ProcessBuilder(debugger, process_to_debug)
    val process = processBuilder.start()

    val reader = BufferedReader(InputStreamReader(process.inputStream))
    val writer = OutputStreamWriter(process.outputStream)

    val channel = Channel<Unit>()

    // Read process data async
    val readJob = launch(Dispatchers.IO) {
        while (isActive) {
            if(!process.isAlive)
            {
                break;
            }
            
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
