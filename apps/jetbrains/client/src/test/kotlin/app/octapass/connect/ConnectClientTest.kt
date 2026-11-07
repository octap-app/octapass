package app.octap.connect

import java.io.File
import java.nio.file.Path
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

private fun failureOf(call: () -> Unit): ConnectException = assertThrows(ConnectException::class.java, call)

/** Every test runs on a real Unix socket and on loopback. */
@RunWith(Parameterized::class)
class ConnectClientTest(private val transport: String) {
    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun transports() = listOf("socket", "loopback")
    }

    private lateinit var dir: Path
    private lateinit var connect: FakeConnect

    private fun client(token: String? = TOKEN) = ConnectClient(connect.endpoint, token)

    @Before
    fun start() {
        dir = FakeConnect.tempDir()
        connect = if (transport == "socket") FakeConnect.onSocket(dir) else FakeConnect.onLoopback()
    }

    @After
    fun stop() {
        connect.close()
        dir.toFile().deleteRecursively()
    }

    @Test
    fun `reads the status without a token`() {
        assertTrue(client(null).status())
        assertFalse("authorization" in connect.seen[0].headers)
    }

    @Test
    fun `pairs with the name as JSON`() {
        val paired = client(null).pair("IntelliJ \"IDEA\"")
        assertEquals(Paired("kU2n6mN0Yk4", TOKEN, 1802592000), paired)
        val request = connect.seen[0]
        assertEquals("""{"name":"IntelliJ \"IDEA\""}""", request.body)
        assertEquals("application/json", request.headers["content-type"])
    }

    @Test
    fun `lists names with the bearer token`() {
        val items = client().items()
        assertEquals(
            listOf(
                ItemRef(
                    "Work",
                    "Stripe",
                    "0192f0c8-1c2d-7a00-8000-0000000000aa",
                    "login",
                    listOf(ItemField("username", false), ItemField("password", true)),
                ),
            ),
            items,
        )
        assertEquals("Bearer $TOKEN", connect.seen[0].headers["authorization"])
    }

    @Test
    fun `gives up the token`() {
        client().forget()
        assertEquals("DELETE /v1/clients/self HTTP/1.1", connect.seen[0].requestLine)
    }

    @Test
    fun `never sends an Origin header`() {
        client().status()
        assertFalse("origin" in connect.seen[0].headers)
    }

    @Test
    fun `answers 401 for a wrong or missing token`() {
        val error = failureOf { client("opc1_wrong").items() }
        assertEquals(Failure.UNAUTHORIZED, error.failure)
        assertEquals(401, error.status)
        assertEquals(Failure.UNAUTHORIZED, failureOf { client(null).items() }.failure)
    }

    @Test
    fun `maps the documented errors`() {
        val cases = listOf(
            Triple("400 Bad Request", "bad-request", Failure.BAD_REQUEST),
            Triple("403 Forbidden", "denied", Failure.DENIED),
            Triple("403 Forbidden", "forbidden", Failure.FORBIDDEN),
            Triple("404 Not Found", "not-found", Failure.NOT_FOUND),
            Triple("423 Locked", "locked", Failure.LOCKED),
            Triple("429 Too Many Requests", "busy", Failure.BUSY),
            Triple("500 Internal Server Error", "failed", Failure.FAILED),
        )
        for ((status, code, failure) in cases) {
            connect.override = { refused(status, code, "From the server.") }
            val error = failureOf { client().items() }
            assertEquals(code, failure, error.failure)
            assertEquals("From the server.", error.message)
        }
    }

    @Test
    fun `copes with an error that has no JSON body`() {
        connect.override = { http("423 Locked", "locked", "text/plain") }
        assertEquals(Failure.LOCKED, failureOf { client().items() }.failure)
        connect.override = { http("413 Payload Too Large") }
        assertEquals(Failure.FAILED, failureOf { client().items() }.failure)
    }

    @Test
    fun `refuses a listing it cannot read`() {
        for (body in listOf("nope", """{"items":[{"vault":"Work"}]}""", """{"items":{}}""", """{"items":[]} x""")) {
            connect.override = { http("200 OK", body) }
            assertEquals(body, Failure.BAD_RESPONSE, failureOf { client().items() }.failure)
        }
    }

    @Test
    fun `refuses a reply that isn't HTTP`() {
        connect.override = { "SSH-2.0-OpenSSH\r\n\r\n" }
        assertEquals(Failure.BAD_RESPONSE, failureOf { client().items() }.failure)
    }

    @Test
    fun `refuses an answer that is too big`() {
        connect.override = { http("200 OK", " ".repeat(9 * 1024 * 1024)) }
        assertEquals(Failure.BAD_RESPONSE, failureOf { client().items() }.failure)
    }

    @Test
    fun `reads Arabic names and JSON escapes`() {
        val body = """{"items":[{"vault":"العمل","item":"caf\u00e9 \ud83d\ude00\n","itemId":"1","type":"login","fields":[]}]}"""
        connect.override = { http("200 OK", body) }
        val item = client().items().single()
        assertEquals("العمل", item.vault)
        assertEquals("café \uD83D\uDE00\n", item.item)
    }

    @Test
    fun `reads a chunked answer`() {
        connect.override = {
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n{\"unlock\r\n9\r\ned\":true}\r\n0\r\n\r\n"
        }
        assertTrue(client().status())
    }

    @Test
    fun `reads an answer that ends with the connection`() {
        connect.override = { "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"unlocked\":true}" }
        assertTrue(client().status())
    }

    @Test
    fun `stops waiting for approval when cancelled`() {
        connect.override = { null }
        val start = System.nanoTime()
        val error = failureOf { client(null).pair("IDE") { System.nanoTime() - start > 200_000_000 } }
        assertEquals(Failure.CANCELLED, error.failure)
    }

    @Test
    fun `says so when Connect goes away mid-answer`() {
        connect.override = { "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{" }
        assertEquals(Failure.NOT_RUNNING, failureOf { client().items() }.failure)
    }

    @Test
    fun `says so when Connect hangs up without an answer`() {
        connect.override = { "" }
        assertEquals(Failure.NOT_RUNNING, failureOf { client().items() }.failure)
    }
}

class ConnectEndpointTest {
    private lateinit var dir: Path

    @Before
    fun start() {
        dir = FakeConnect.tempDir()
    }

    @After
    fun stop() {
        dir.toFile().deleteRecursively()
    }

    @Test
    fun `Host names the address on loopback, and localhost when that was configured`() {
        FakeConnect.onLoopback().use { connect ->
            val port = (connect.endpoint as Endpoint.Loopback).port
            ConnectClient(Endpoint.Loopback("127.0.0.1", port)).status()
            ConnectClient(Endpoint.Loopback("localhost", port)).status()
            assertEquals(listOf("127.0.0.1:$port", "localhost:$port"), connect.seen.map { it.headers["host"] })
        }
    }

    @Test
    fun `says Connect isn't running for a file that isn't a live socket`() {
        val stale = dir.resolve("stale.sock").toFile().apply { writeText("") }
        val error = failureOf { ConnectClient(Endpoint.Socket(stale.path)).status() }
        assertEquals(Failure.NOT_RUNNING, error.failure)
        val missing = dir.resolve("missing.sock").toString()
        assertEquals(Failure.NOT_RUNNING, failureOf { ConnectClient(Endpoint.Socket(missing)).status() }.failure)
    }

    @Test
    fun `says Connect isn't running for a closed port`() {
        val endpoint = FakeConnect.onLoopback().use { it.endpoint }
        assertEquals(Failure.NOT_RUNNING, failureOf { ConnectClient(endpoint).status() }.failure)
    }

    @Test
    fun `parses what the docs allow`() {
        assertEquals(Endpoint.Socket("/run/connect.sock"), parseEndpoint("unix:/run/connect.sock"))
        assertEquals(Endpoint.Loopback("127.0.0.1", 8123), parseEndpoint("http://127.0.0.1:8123"))
        assertEquals(Endpoint.Loopback("127.0.0.1", 8123), parseEndpoint("http://127.0.0.1:8123/"))
        assertEquals(Endpoint.Loopback("localhost", 8123), parseEndpoint("http://localhost:8123"))
    }

    @Test
    fun `refuses anything else, so a token never leaves the machine`() {
        val bad = listOf(
            "unix:",
            "http://example.com:8123",
            "https://127.0.0.1:8123",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:70000",
            "http://127.0.0.1:80@example.com",
            "http://127.0.0.1:8123/v1",
            "http://localhost.example.com:8123",
            "127.0.0.1:8123",
        )
        for (text in bad) {
            assertNull(text, parseEndpoint(text))
        }
    }

    @Test
    fun `follows the table of folders in the docs`() {
        assertEquals(
            "/Users/me/Library/Application Support/com.octapass.connect",
            connectFolder(Place(emptyMap(), Os.MAC, "/Users/me")),
        )
        assertEquals(
            "/home/me/.local/share/com.octapass.connect",
            connectFolder(Place(emptyMap(), Os.LINUX, "/home/me")),
        )
        assertEquals(
            "/data/com.octapass.connect",
            connectFolder(Place(mapOf("XDG_DATA_HOME" to "/data"), Os.LINUX, "/home/me")),
        )
        assertEquals(
            "/home/me/.local/share/com.octapass.connect",
            connectFolder(Place(mapOf("XDG_DATA_HOME" to "relative"), Os.LINUX, "/home/me")),
        )
        assertEquals(
            "C:\\Users\\me\\AppData\\Roaming\\com.octapass.connect",
            connectFolder(Place(mapOf("APPDATA" to "C:\\Users\\me\\AppData\\Roaming"), Os.WINDOWS, "C:\\Users\\me")),
        )
    }

    private fun place(extra: Map<String, String> = emptyMap()): Pair<Place, File> {
        val place = Place(mapOf("XDG_DATA_HOME" to dir.toString()) + extra, Os.LINUX, "/nowhere")
        return place to File(connectFolder(place)).apply { mkdirs() }
    }

    @Test
    fun `takes OCTAPASS_CONNECT first`() {
        val (place, folder) = place(mapOf("OCTAPASS_CONNECT" to "http://127.0.0.1:1234"))
        File(folder, "connect.sock").writeText("")
        File(folder, "connect.port").writeText("9000")
        assertEquals(Endpoint.Loopback("127.0.0.1", 1234), findEndpoint(place))
    }

    @Test
    fun `ignores an empty OCTAPASS_CONNECT`() {
        val (place, folder) = place(mapOf("OCTAPASS_CONNECT" to ""))
        File(folder, "connect.port").writeText("9000")
        assertEquals(Endpoint.Loopback("127.0.0.1", 9000), findEndpoint(place))
    }

    @Test
    fun `stops at an OCTAPASS_CONNECT it can't read, as the CLI does`() {
        val (place, folder) = place(mapOf("OCTAPASS_CONNECT" to "http://example.com:9000"))
        File(folder, "connect.port").writeText("9000")
        assertEquals(Failure.BAD_ENDPOINT, failureOf { findEndpoint(place) }.failure)
    }

    @Test
    fun `takes the socket over the port file`() {
        val (place, folder) = place()
        File(folder, "connect.sock").writeText("")
        File(folder, "connect.port").writeText("9000")
        assertEquals(Endpoint.Socket(File(folder, "connect.sock").path), findEndpoint(place))
    }

    @Test
    fun `reads the port file, with its line ending`() {
        val (place, folder) = place()
        File(folder, "connect.port").writeText("9000\n")
        assertEquals(Endpoint.Loopback("127.0.0.1", 9000), findEndpoint(place))
    }

    @Test
    fun `says Connect isn't running when there is neither, or no port in the file`() {
        val (place, folder) = place()
        assertEquals(Failure.NOT_RUNNING, failureOf { findEndpoint(place) }.failure)
        File(folder, "connect.port").writeText("nonsense")
        assertEquals(Failure.NOT_RUNNING, failureOf { findEndpoint(place) }.failure)
    }
}
