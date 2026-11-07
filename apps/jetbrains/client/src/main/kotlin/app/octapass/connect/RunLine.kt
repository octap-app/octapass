// The line typed into the terminal. The terminal's `octapass run` reads the secrets, so no value
// passes through the plugin.

package app.octap.connect

private enum class Shell { POSIX, POWERSHELL, CMD }

private fun family(shell: String, os: Os): Shell {
    val name = shell.substringAfterLast('/').substringAfterLast('\\').lowercase()
    return when {
        name.startsWith("pwsh") || name.startsWith("powershell") -> Shell.POWERSHELL
        name == "cmd.exe" || name == "cmd" -> Shell.CMD
        os == Os.WINDOWS && name.isEmpty() -> Shell.POWERSHELL
        else -> Shell.POSIX
    }
}

private fun program(path: String, shell: Shell): String = when {
    shell == Shell.POSIX ->
        if (Regex("""[\w./:=@%+,~-]+""").matches(path)) path else "'${path.replace("'", "'\\''")}'"
    Regex("""[\w./:\\~-]+""").matches(path) -> path
    shell == Shell.POWERSHELL -> "& '${path.replace("'", "''")}'"
    else -> "\"$path\""
}

/** `octapass run -- <command>`, with the command as the person typed it. */
fun runLine(cliPath: String, command: String, shell: String, os: Os): String =
    "${program(cliPath.trim().ifEmpty { "octapass" }, family(shell, os))} run -- ${command.trim()}"
