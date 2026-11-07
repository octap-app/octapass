package app.octap.connect

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

const val TOKEN = "opc1_test"

val ITEMS = """
    {"items":[{"vault":"Work","item":"Stripe","itemId":"0192f0c8-1c2d-7a00-8000-0000000000aa","type":"login",
    "fields":[{"name":"username","secret":false},{"name":"password","secret":true}]}]}
""".trimIndent()

class Seen(val requestLine: String, val headers: Map<String, String>, val body: String)

/** Raw bytes to answer with, or null to keep the connection open and say nothing. */
typealias Answer = (Seen) -> String?

fun http(status: String, body: String = "", contentType: String = "application/json"): String {
    val length = body.toByteArray().size
    return "HTTP/1.1 $status\r\nContent-Type: $contentType\r\nContent-Length: $length\r\nConnection: close\r\n\r\n$body"
}

fun refused(status: String, code: String, message: String) =
    http(status, """{"error":{"code":"$code","message":"$message"}}""")

/**
 * A server with the rules of the real one (apps/desktop/crates/connect/src/server.rs): the Host and
 * Origin checks on loopback, the bearer token, and JSON with its Content-Type. On a real Unix
 * socket, or on loopback.
 */
class FakeConnect private constructor(
    private val server: ServerSocketChannel,
    val endpoint: Endpoint,
    private val hosts: List<String>,
) : AutoCloseable {
    val seen = CopyOnWriteArrayList<Seen>()

    @Volatile
    var override: Answer? = null

    private val open = CopyOnWriteArrayList<SocketChannel>()

    init {
        thread(isDaemon = true) {
            try {
                while (true) {
                    val channel = server.accept()
                    open += channel
                    thread(isDaemon = true) { serve(channel) }
                }
            } catch (_: java.io.IOException) {
                // Closed.
            }
        }
    }

    private fun serve(channel: SocketChannel) {
        try {
            val request = read(channel)
            seen += request
            val answer = guard(request) ?: override.let { if (it != null) it(request) else route(request) } ?: return
            val bytes = ByteBuffer.wrap(answer.toByteArray())
            while (bytes.hasRemaining()) {
                channel.write(bytes)
            }
            channel.close()
        } catch (_: java.io.IOException) {
            // The client went away.
        }
    }

    private fun read(channel: SocketChannel): Seen {
        val buffer = ByteBuffer.allocate(64 * 1024)
        while (true) {
            if (channel.read(buffer) < 0) {
                throw java.io.IOException("ended")
            }
            val text = String(buffer.array(), 0, buffer.position())
            val split = text.indexOf("\r\n\r\n")
            if (split < 0) {
                continue
            }
            val lines = text.substring(0, split).split("\r\n")
            val headers = lines.drop(1).associate {
                it.substringBefore(':').trim().lowercase() to it.substringAfter(':').trim()
            }
            val length = headers["content-length"]?.toInt() ?: 0
            val body = text.substring(split + 4)
            if (body.toByteArray().size >= length) {
                return Seen(lines[0], headers, body)
            }
        }
    }

    private fun guard(request: Seen): String? {
        val refused = hosts.isNotEmpty() && ("origin" in request.headers || request.headers["host"] !in hosts)
        return if (refused) refused("403 Forbidden", "forbidden", "Local programs only.") else null
    }

    private fun route(request: Seen): String {
        val authorized = request.headers["authorization"] == "Bearer $TOKEN"
        val route = request.requestLine.removeSuffix(" HTTP/1.1")
        return when {
            route == "GET /v1/status" -> http("200 OK", """{"unlocked":true}""")
            route == "POST /v1/clients" ->
                if (request.headers["content-type"] != "application/json") {
                    http("415 Unsupported Media Type", "Expected application/json", "text/plain")
                } else {
                    http("201 Created", """{"id":"kU2n6mN0Yk4","token":"$TOKEN","expiresAt":1802592000}""")
                }
            !authorized -> refused("401 Unauthorized", "unauthorized", "No token.")
            route == "GET /v1/items" -> http("200 OK", ITEMS)
            route == "DELETE /v1/clients/self" -> "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
            else -> http("404 Not Found")
        }
    }

    override fun close() {
        server.close()
        open.forEach { it.close() }
    }

    companion object {
        fun onSocket(dir: Path): FakeConnect {
            val path = dir.resolve("connect-${System.nanoTime()}.sock")
            val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
            server.bind(UnixDomainSocketAddress.of(path))
            return FakeConnect(server, Endpoint.Socket(path.toString()), emptyList())
        }

        fun onLoopback(): FakeConnect {
            val server = ServerSocketChannel.open()
            server.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0))
            val port = (server.localAddress as InetSocketAddress).port
            return FakeConnect(
                server,
                Endpoint.Loopback("127.0.0.1", port),
                listOf("127.0.0.1:$port", "localhost:$port"),
            )
        }

        /** Short: a socket path has to fit in about 100 characters. */
        fun tempDir(): Path = Files.createTempDirectory(Path.of("/tmp"), "op-")
    }
}
