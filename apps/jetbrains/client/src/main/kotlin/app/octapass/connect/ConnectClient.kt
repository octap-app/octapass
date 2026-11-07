// The client of Octa Pass Connect (docs/developers/connect-api.md): one HTTP/1.1 request per
// connection, written by hand over a SocketChannel, so a Unix socket and loopback share all of it.
// No IntelliJ imports. It has no way to ask for a value, on purpose: this plugin only holds names.

package app.octap.connect

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel

private const val FOLDER = "com.octapass.connect"
private const val MAX_RESPONSE = 8 * 1024 * 1024
private const val REQUEST_TIMEOUT = 30_000L

/** Connect waits up to two minutes for the person to answer. */
private const val APPROVAL_TIMEOUT = 130_000L
private const val POLL = 100L

sealed interface Endpoint {
    data class Socket(val path: String) : Endpoint

    data class Loopback(val host: String, val port: Int) : Endpoint
}

enum class Failure {
    NOT_RUNNING,
    BAD_ENDPOINT,
    TIMED_OUT,
    CANCELLED,
    BAD_RESPONSE,
    BAD_REQUEST,
    UNAUTHORIZED,
    DENIED,
    FORBIDDEN,
    NOT_FOUND,
    LOCKED,
    BUSY,
    FAILED,
}

class ConnectException(
    val failure: Failure,
    message: String = "",
    val status: Int? = null,
) : Exception(message.ifEmpty { failure.name })

data class Paired(val id: String, val token: String, val expiresAt: Long)

data class ItemField(val name: String, val secret: Boolean)

data class ItemRef(
    val vault: String,
    val item: String,
    val itemId: String,
    val type: String,
    val fields: List<ItemField>,
)

enum class Os { MAC, LINUX, WINDOWS }

/** What finding Connect depends on, so it can be tested on any system. */
data class Place(val env: Map<String, String>, val os: Os, val home: String) {
    companion object {
        fun current(env: Map<String, String> = System.getenv()): Place {
            val name = System.getProperty("os.name").lowercase()
            val os = when {
                name.startsWith("mac") -> Os.MAC
                name.startsWith("windows") -> Os.WINDOWS
                else -> Os.LINUX
            }
            return Place(env, os, System.getProperty("user.home"))
        }
    }
}

private fun join(os: Os, vararg parts: String): String {
    val separator = if (os == Os.WINDOWS) "\\" else "/"
    return parts.joinToString(separator) { it.trimEnd('/', '\\') }
}

/** The Connect folder in this system's per-user data folder. */
fun connectFolder(place: Place): String {
    val (env, os, home) = place
    return when (os) {
        Os.WINDOWS -> join(os, env["APPDATA"].orEmpty().ifEmpty { join(os, home, "AppData", "Roaming") }, FOLDER)
        Os.MAC -> join(os, home, "Library", "Application Support", FOLDER)
        // The XDG spec has relative paths ignored, and the service does the same.
        Os.LINUX -> {
            val data = env["XDG_DATA_HOME"]?.takeIf { it.startsWith("/") }
            join(os, data ?: join(os, home, ".local", "share"), FOLDER)
        }
    }
}

private val LOOPBACK = Regex("""^http://(127\.0\.0\.1|localhost):(\d{1,5})/?$""")

private fun portNumber(text: String): Int? =
    text.takeIf { Regex("""\d{1,5}""").matches(it) }?.toInt()?.takeIf { it in 1..65535 }

/** `unix:/path`, `http://127.0.0.1:<port>` or `http://localhost:<port>`. Nothing else, so a token never leaves the machine. */
fun parseEndpoint(text: String): Endpoint? {
    if (text.startsWith("unix:")) {
        return text.removePrefix("unix:").takeIf { it.isNotEmpty() }?.let(Endpoint::Socket)
    }
    val match = LOOPBACK.find(text) ?: return null
    val port = portNumber(match.groupValues[2]) ?: return null
    return Endpoint.Loopback(match.groupValues[1], port)
}

/** In the order of the docs: `OCTAPASS_CONNECT`, the socket, the port file. */
fun findEndpoint(place: Place): Endpoint {
    val configured = place.env["OCTAPASS_CONNECT"]
    if (!configured.isNullOrEmpty()) {
        return parseEndpoint(configured) ?: throw ConnectException(Failure.BAD_ENDPOINT)
    }
    val folder = connectFolder(place)
    val socket = join(place.os, folder, "connect.sock")
    if (File(socket).exists()) {
        return Endpoint.Socket(socket)
    }
    val text = try {
        File(join(place.os, folder, "connect.port")).readText()
    } catch (_: IOException) {
        throw ConnectException(Failure.NOT_RUNNING)
    }
    val port = portNumber(text.trim()) ?: throw ConnectException(Failure.NOT_RUNNING)
    return Endpoint.Loopback("127.0.0.1", port)
}

private class Reply(val status: Int, val body: String)

class ConnectClient(private val endpoint: Endpoint, private val token: String? = null) {
    fun status(): Boolean {
        val value = json("GET", "/v1/status") as? Map<*, *>
        return value?.get("unlocked") as? Boolean ?: throw ConnectException(Failure.BAD_RESPONSE)
    }

    /** Waits while the person is asked. It stops soon after [cancelled] turns true. */
    fun pair(name: String, cancelled: () -> Boolean = { false }): Paired {
        val body = """{"name":${Json.quote(name)}}"""
        val value = json("POST", "/v1/clients", body, APPROVAL_TIMEOUT, cancelled) as? Map<*, *>
        val id = value?.get("id") as? String
        val token = value?.get("token") as? String
        val expiresAt = value?.get("expiresAt") as? Double
        if (id == null || token.isNullOrEmpty() || expiresAt == null) {
            throw ConnectException(Failure.BAD_RESPONSE)
        }
        return Paired(id, token, expiresAt.toLong())
    }

    /** Gives up this client's token. */
    fun forget() {
        call("DELETE", "/v1/clients/self")
    }

    /** Names only, never values. */
    fun items(): List<ItemRef> {
        val value = json("GET", "/v1/items") as? Map<*, *>
        val items = value?.get("items") as? List<*> ?: throw ConnectException(Failure.BAD_RESPONSE)
        return items.map { item(it) ?: throw ConnectException(Failure.BAD_RESPONSE) }
    }

    private fun item(value: Any?): ItemRef? {
        val item = value as? Map<*, *> ?: return null
        val fields = (item["fields"] as? List<*>)?.map { field(it) ?: return null } ?: return null
        return ItemRef(
            vault = item["vault"] as? String ?: return null,
            item = item["item"] as? String ?: return null,
            itemId = item["itemId"] as? String ?: return null,
            type = item["type"] as? String ?: return null,
            fields = fields,
        )
    }

    private fun field(value: Any?): ItemField? {
        val field = value as? Map<*, *> ?: return null
        return ItemField(
            name = field["name"] as? String ?: return null,
            secret = field["secret"] as? Boolean ?: return null,
        )
    }

    private fun json(
        method: String,
        path: String,
        body: String? = null,
        timeout: Long = REQUEST_TIMEOUT,
        cancelled: () -> Boolean = { false },
    ): Any? {
        val reply = call(method, path, body, timeout, cancelled)
        return try {
            Json(reply.body).parse()
        } catch (_: IllegalArgumentException) {
            throw ConnectException(Failure.BAD_RESPONSE)
        }
    }

    private fun call(
        method: String,
        path: String,
        body: String? = null,
        timeout: Long = REQUEST_TIMEOUT,
        cancelled: () -> Boolean = { false },
    ): Reply {
        val reply = exchange(request(method, path, body), timeout, cancelled)
        if (reply.status in 200..299) {
            return reply
        }
        throw refusal(reply)
    }

    private fun request(method: String, path: String, body: String?): ByteArray {
        val host = when (endpoint) {
            is Endpoint.Socket -> "localhost"
            is Endpoint.Loopback -> "${endpoint.host}:${endpoint.port}"
        }
        val payload = body?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
        val head = buildString {
            append("$method $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n")
            token?.let { append("Authorization: Bearer $it\r\n") }
            if (body != null) {
                append("Content-Type: application/json\r\nContent-Length: ${payload.size}\r\n")
            }
            append("\r\n")
        }
        return head.toByteArray(Charsets.US_ASCII) + payload
    }

    private fun address(): SocketAddress = when (endpoint) {
        is Endpoint.Socket -> UnixDomainSocketAddress.of(endpoint.path)
        // Always the address itself: `localhost` could resolve to ::1, where Connect never listens.
        is Endpoint.Loopback ->
            InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), endpoint.port)
    }

    private fun exchange(request: ByteArray, timeout: Long, cancelled: () -> Boolean): Reply {
        val deadline = System.nanoTime() + timeout * 1_000_000
        try {
            SocketChannel.open(address()).use { channel ->
                channel.configureBlocking(false)
                Selector.open().use { selector ->
                    return converse(channel, selector, ByteBuffer.wrap(request), deadline, cancelled)
                }
            }
        } catch (error: IOException) {
            throw ConnectException(Failure.NOT_RUNNING, error.message.orEmpty())
        }
    }

    private fun converse(
        channel: SocketChannel,
        selector: Selector,
        outgoing: ByteBuffer,
        deadline: Long,
        cancelled: () -> Boolean,
    ): Reply {
        val key = channel.register(selector, SelectionKey.OP_WRITE)
        val incoming = ByteArrayOutputStream()
        val buffer = ByteBuffer.allocate(16 * 1024)
        while (true) {
            if (cancelled()) {
                throw ConnectException(Failure.CANCELLED)
            }
            if (System.nanoTime() > deadline) {
                throw ConnectException(Failure.TIMED_OUT)
            }
            selector.select(POLL)
            selector.selectedKeys().clear()
            if (key.isWritable) {
                channel.write(outgoing)
                if (!outgoing.hasRemaining()) {
                    key.interestOps(SelectionKey.OP_READ)
                }
            }
            if (!key.isReadable) {
                continue
            }
            buffer.clear()
            val read = channel.read(buffer)
            if (read > 0) {
                incoming.write(buffer.array(), 0, read)
                if (incoming.size() > MAX_RESPONSE) {
                    throw ConnectException(Failure.BAD_RESPONSE)
                }
            }
            parse(incoming.toByteArray(), ended = read < 0)?.let { return it }
            if (read < 0) {
                throw ConnectException(Failure.NOT_RUNNING)
            }
        }
    }
}

/** The whole reply, or null while more is to come. */
private fun parse(bytes: ByteArray, ended: Boolean): Reply? {
    val split = indexOf(bytes, "\r\n\r\n".toByteArray(), 0)
    if (split < 0) {
        return null
    }
    val lines = String(bytes, 0, split, Charsets.ISO_8859_1).split("\r\n")
    val status = lines[0].split(' ').getOrNull(1)?.takeIf { lines[0].startsWith("HTTP/1.") }?.toIntOrNull()
        ?: throw ConnectException(Failure.BAD_RESPONSE)
    val headers = lines.drop(1).associate {
        it.substringBefore(':').trim().lowercase() to it.substringAfter(':').trim()
    }
    val body = bytes.copyOfRange(split + 4, bytes.size)
    val whole = when {
        headers["transfer-encoding"]?.lowercase() == "chunked" -> unchunk(body)
        "content-length" in headers -> {
            val length = headers["content-length"]?.toIntOrNull()
                ?: throw ConnectException(Failure.BAD_RESPONSE)
            if (body.size >= length) body.copyOf(length) else null
        }
        // Delimited by the end of the connection.
        ended -> body
        else -> null
    }
    return whole?.let { Reply(status, String(it, Charsets.UTF_8)) }
}

/** The decoded body, or null if the last chunk hasn't arrived. */
private fun unchunk(bytes: ByteArray): ByteArray? {
    val out = ByteArrayOutputStream()
    var at = 0
    while (true) {
        val end = indexOf(bytes, "\r\n".toByteArray(), at)
        if (end < 0) {
            return null
        }
        val size = String(bytes, at, end - at, Charsets.ISO_8859_1).substringBefore(';').trim().toIntOrNull(16)
            ?: throw ConnectException(Failure.BAD_RESPONSE)
        if (size == 0) {
            return out.toByteArray()
        }
        if (size < 0 || end + 2 + size > bytes.size) {
            return null
        }
        out.write(bytes, end + 2, size)
        at = end + 2 + size + 2
    }
}

private fun indexOf(bytes: ByteArray, needle: ByteArray, from: Int): Int {
    for (at in from..bytes.size - needle.size) {
        if (needle.indices.all { bytes[at + it] == needle[it] }) {
            return at
        }
    }
    return -1
}

/** The status decides, and the body only tells `denied` from `forbidden`. Not every error has the documented body. */
private fun refusal(reply: Reply): ConnectException {
    val error = try {
        (Json(reply.body).parse() as? Map<*, *>)?.get("error") as? Map<*, *>
    } catch (_: IllegalArgumentException) {
        null
    }
    val failure = when (reply.status) {
        400 -> Failure.BAD_REQUEST
        401 -> Failure.UNAUTHORIZED
        403 -> if (error?.get("code") == "denied") Failure.DENIED else Failure.FORBIDDEN
        404 -> Failure.NOT_FOUND
        423 -> Failure.LOCKED
        429 -> Failure.BUSY
        else -> Failure.FAILED
    }
    return ConnectException(failure, error?.get("message") as? String ?: "", reply.status)
}

/** A small JSON reader, so the client needs no library: objects, lists, strings, numbers as Double, booleans, null. */
private class Json(private val text: String) {
    private var at = 0

    companion object {
        private const val MAX_DEPTH = 32

        fun quote(value: String): String = buildString {
            append('"')
            for (char in value) {
                when {
                    char == '"' -> append("\\\"")
                    char == '\\' -> append("\\\\")
                    char < ' ' -> append("\\u%04x".format(char.code))
                    else -> append(char)
                }
            }
            append('"')
        }
    }

    fun parse(): Any? {
        val value = value(0)
        space()
        require(at == text.length) { "trailing text" }
        return value
    }

    private fun space() {
        while (at < text.length && text[at] in " \t\r\n") at++
    }

    private fun peek(): Char {
        require(at < text.length) { "ended early" }
        return text[at]
    }

    private fun expect(char: Char) {
        require(peek() == char) { "expected $char" }
        at++
    }

    private fun word(word: String, value: Any?): Any? {
        require(text.startsWith(word, at)) { "expected $word" }
        at += word.length
        return value
    }

    private fun value(depth: Int): Any? {
        require(depth < MAX_DEPTH) { "too deep" }
        space()
        return when (peek()) {
            '{' -> obj(depth)
            '[' -> list(depth)
            '"' -> string()
            't' -> word("true", true)
            'f' -> word("false", false)
            'n' -> word("null", null)
            else -> number()
        }
    }

    private fun obj(depth: Int): Map<String, Any?> {
        expect('{')
        val out = LinkedHashMap<String, Any?>()
        space()
        if (peek() == '}') {
            at++
            return out
        }
        while (true) {
            space()
            val key = string()
            space()
            expect(':')
            out[key] = value(depth + 1)
            space()
            if (peek() == '}') {
                at++
                return out
            }
            expect(',')
        }
    }

    private fun list(depth: Int): List<Any?> {
        expect('[')
        val out = ArrayList<Any?>()
        space()
        if (peek() == ']') {
            at++
            return out
        }
        while (true) {
            out += value(depth + 1)
            space()
            if (peek() == ']') {
                at++
                return out
            }
            expect(',')
        }
    }

    private fun string(): String {
        expect('"')
        val out = StringBuilder()
        while (true) {
            val char = peek()
            at++
            when {
                char == '"' -> return out.toString()
                char == '\\' -> out.append(escape())
                else -> {
                    require(char >= ' ') { "control character" }
                    out.append(char)
                }
            }
        }
    }

    private fun escape(): Char {
        val char = peek()
        at++
        return when (char) {
            '"', '\\', '/' -> char
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> {
                require(at + 4 <= text.length) { "ended early" }
                val code = text.substring(at, at + 4).toIntOrNull(16)
                requireNotNull(code) { "bad escape" }
                at += 4
                code.toChar()
            }
            else -> throw IllegalArgumentException("bad escape")
        }
    }

    private fun number(): Double {
        val start = at
        while (at < text.length && text[at] in "+-.eE0123456789") at++
        return requireNotNull(text.substring(start, at).toDoubleOrNull()) { "bad number" }
    }
}
