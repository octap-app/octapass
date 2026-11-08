"""The skill against the real CLI: every command, flag and value it writes must exist in `--help`.

    cargo build -p octapass-cli
    python3 -m unittest discover -s skills/octapass-cli/tests

The binary is `OCTAPASS_BIN`, else `target/debug/octapass` or `target/release/octapass` in this
checkout. Without one the tests against it are skipped, unless `OCTAPASS_BIN` is set (CI sets it),
when a missing binary is a failure. The parser tests below run either way.
"""
import os
import re
import shlex
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
REPO = SKILL.parents[1]
FILES = [SKILL / "SKILL.md", *sorted((SKILL / "references").glob("*.md"))]


# ---------------------------------------------------------------------------------------------
# Reading `--help`
# ---------------------------------------------------------------------------------------------

OPTION = re.compile(r"^\s+(?:(-[A-Za-z0-9]), )?(--[A-Za-z0-9][\w-]*)(?: <[^>]+>)?(.*)$")
SHORT_ONLY = re.compile(r"^\s+(-[A-Za-z0-9])(?: <[^>]+>)?(\s.*)?$")
ARGUMENT = re.compile(r"^\s+[<\[]([A-Z0-9_|]+)[>\]](?:\.\.\.)?(.*)$")
INLINE_VALUES = re.compile(r"\[possible values: ([^\]]+)\]")
LISTED_VALUE = re.compile(r"^\s+- ([\w.-]+)(?::|$)")


class Command:
    """One node of the help tree."""

    def __init__(self, path):
        self.path = tuple(path)
        self.children = {}
        self.flags = {}  # "--vault" / "-n" -> takes a value
        self.values = {}  # "--format" -> {"dotenv", ...}
        self.positional_values = []  # possible values of each positional, in order (None: any)


def parse_help(text, path=()):
    """A `Command` from one `--help` page (children only by name)."""
    command = Command(path)
    section = None
    current = None  # the flag or positional index the following lines describe
    for line in text.splitlines():
        if re.match(r"^[A-Z][A-Za-z ]*:\s*$", line):
            section = line.strip()[:-1]
            current = None
            continue
        if section == "Commands":
            match = re.match(r"^  (\S+)", line)
            if match and match.group(1) != "help":
                command.children[match.group(1)] = None
            continue
        if section == "Options":
            match = OPTION.match(line)
            short = SHORT_ONLY.match(line) if not match else None
            if match:
                short_flag, long_flag, rest = match.groups()
                takes_value = bool(re.search(r"--[\w-]+ <", line))
                for flag in filter(None, (short_flag, long_flag)):
                    command.flags[flag] = takes_value
                current = ("flag", long_flag, short_flag)
                inline = INLINE_VALUES.search(rest or "")
                if inline:
                    add_values(command, current, [v.strip() for v in inline.group(1).split(",")])
                continue
            if short:
                command.flags[short.group(1)] = "<" in line
                current = ("flag", short.group(1), None)
                continue
        if section == "Arguments":
            match = ARGUMENT.match(line)
            if match:
                command.positional_values.append(None)
                current = ("arg", len(command.positional_values) - 1)
                inline = INLINE_VALUES.search(match.group(2))
                if inline:
                    add_values(command, current, [v.strip() for v in inline.group(1).split(",")])
                continue
        if current is not None:
            inline = INLINE_VALUES.search(line)
            if inline:
                add_values(command, current, [v.strip() for v in inline.group(1).split(",")])
            listed = LISTED_VALUE.match(line)
            if listed:
                add_values(command, current, [listed.group(1)])
    return command


def add_values(command, current, values):
    if current[0] == "flag":
        for flag in filter(None, current[1:]):
            command.values.setdefault(flag, set()).update(values)
    else:
        index = current[1]
        command.positional_values[index] = (command.positional_values[index] or set()) | set(values)


def help_tree(binary):
    """Every command under `octapass`, by path, read from `--help` in parallel, level by level."""
    def page(path):
        done = subprocess.run([binary, *path, "--help"], capture_output=True, text=True, timeout=60)
        if done.returncode != 0:
            raise AssertionError(f"`octapass {' '.join(path)} --help` exited {done.returncode}: {done.stderr}")
        return parse_help(done.stdout, path)

    tree = {}
    level = [()]
    with ThreadPoolExecutor(max_workers=8) as pool:
        while level:
            commands = list(pool.map(page, level))
            level = []
            for command in commands:
                tree[command.path] = command
                level.extend(command.path + (child,) for child in command.children)
    return tree


# ---------------------------------------------------------------------------------------------
# Reading the skill
# ---------------------------------------------------------------------------------------------

FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.S | re.M)
INLINE_CODE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
INVOCATION = re.compile(r"(?<![\w/.-])octapass(?= )")
PLACEHOLDER = re.compile(r"<[A-Za-z][\w .:/-]*>")
BARE_FLAG = re.compile(r"^(-[A-Za-z0-9]|--[A-Za-z0-9][\w-]*)(?:[ =].*)?$")


class Mention:
    def __init__(self, file, line, text, row_flags=()):
        self.file, self.line, self.text, self.row_flags = file, line, text, row_flags

    def where(self):
        return f"{self.file.relative_to(REPO)}:{self.line}: {self.text}"


def code_snippets(markdown):
    """(line number, code) for every fenced line and every inline code span outside fences."""
    snippets = []
    fenced = set()
    for block in FENCE.finditer(markdown):
        first = markdown.count("\n", 0, block.start()) + 1
        start = markdown.count("\n", 0, block.start(1)) + 1
        for offset, line in enumerate(block.group(1).splitlines()):
            snippets.append((start + offset, line, "fence", None))
        fenced.update(range(first, markdown.count("\n", 0, block.end()) + 2))
    for number, line in enumerate(markdown.splitlines(), 1):
        if number in fenced:
            continue
        if line.startswith("|"):
            spans = [m.group(1) for m in INLINE_CODE.finditer(line)]
            for span in spans:
                snippets.append((number, span, "inline", spans))
        else:
            for match in INLINE_CODE.finditer(line):
                snippets.append((number, match.group(1), "inline", None))
    return snippets


def invocations(code):
    """The words of each `octapass …` command in a line of code, up to the shell's next operator."""
    found = []
    for match in INVOCATION.finditer(code):
        rest = code[match.end():]
        before = code[: match.start()]
        if before.endswith("$("):
            rest = rest.split(")", 1)[0]
        elif before.endswith("`"):
            rest = rest.split("`", 1)[0]
        rest = PLACEHOLDER.sub("PLACEHOLDER", rest)
        lexer = shlex.shlex(rest, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words = []
        try:
            for word in lexer:
                if word and set(word) <= set("();<>|&"):
                    break
                words.append(word)
        except ValueError as error:
            raise AssertionError(f"Can't read `octapass{rest}`: {error}") from error
        found.append(words)
    return found


def mentions():
    """Every `octapass …` command and every bare flag written in the skill."""
    commands, flags = [], []
    for file in FILES:
        for line, code, kind, row in code_snippets(file.read_text(encoding="utf-8")):
            for words in invocations(code):
                row_flags = ()
                if row and code == row[0]:
                    row_flags = tuple(s for s in row[1:] if BARE_FLAG.match(s) and not INVOCATION.search(s))
                commands.append((Mention(file, line, f"octapass {' '.join(words)}", row_flags), words))
            if kind == "inline" and BARE_FLAG.match(code) and not INVOCATION.search(code):
                flags.append(Mention(file, line, code))
    return commands, flags


def check(tree, words):
    """The command path these words reach, and a list of problems."""
    node = tree[()]
    problems = []
    positional = 0
    words = list(words)
    i = 0
    while i < len(words):
        word = words[i].strip("[]")
        i += 1
        if word in ("", "…", "...", "PLACEHOLDER") or word.startswith("PLACEHOLDER"):
            if not node.children:
                positional += 1
            continue
        if word == "--":
            break
        if word.startswith("-") and len(word) > 1 and not re.match(r"^-\d", word):
            flag, _, inline_value = word.partition("=")
            if flag not in node.flags:
                problems.append(f"`{flag}` isn't an option of `octapass {' '.join(node.path)}`")
                continue
            if node.flags[flag]:
                value = inline_value or (words[i] if i < len(words) else None)
                if not inline_value:
                    i += 1
                allowed = node.values.get(flag)
                if allowed and value and plain_value(value) and value not in allowed:
                    problems.append(f"`{flag} {value}`: `octapass {' '.join(node.path)}` takes {sorted(allowed)}")
            continue
        if node.children:
            if word not in node.children:
                problems.append(f"`{word}` isn't a command of `octapass {' '.join(node.path)}`".replace("octapass `", "octapass`"))
                break
            node = tree[node.path + (word,)]
            continue
        if positional < len(node.positional_values):
            allowed = node.positional_values[positional]
            if allowed and plain_value(word) and word not in allowed:
                problems.append(f"`{word}`: `octapass {' '.join(node.path)}` takes {sorted(allowed)}")
        positional += 1
    return node, problems


def plain_value(value):
    return not any(mark in value for mark in "$<…*{") and value != "PLACEHOLDER"


def skill_text():
    return "\n".join(file.read_text(encoding="utf-8") for file in FILES)


def find_binary():
    named = os.environ.get("OCTAPASS_BIN")
    if named:
        return named, True
    for build in ("debug", "release"):
        candidate = REPO / "target" / build / ("octapass.exe" if os.name == "nt" else "octapass")
        if candidate.exists():
            return str(candidate), False
    return None, False


# ---------------------------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------------------------

class SkillAgainstTheCli(unittest.TestCase):
    """Needs a built `octapass`."""

    @classmethod
    def setUpClass(cls):
        binary, named = find_binary()
        if binary is None:
            raise unittest.SkipTest("No octapass binary: run `cargo build -p octapass-cli` or set OCTAPASS_BIN.")
        if named and not Path(binary).exists():
            raise AssertionError(f"OCTAPASS_BIN={binary} doesn't exist.")
        cls.tree = help_tree(binary)
        cls.commands, cls.flags = mentions()

    def test_the_help_tree_was_read(self):
        # A parser that silently reads nothing would pass every other test.
        self.assertGreater(len(self.tree), 50)
        self.assertIn(("env", "export"), self.tree)
        self.assertEqual(self.tree[("env", "export")].values["--format"], {"dotenv", "json", "shell", "powershell", "docker"})
        self.assertIn("-n", self.tree[("get",)].flags)
        self.assertGreater(len(self.commands), 150)

    def test_every_command_flag_and_value_exists(self):
        problems = []
        for mention, words in self.commands:
            node, found = check(self.tree, words)
            problems += [f"{mention.where()}\n    {problem}" for problem in found]
            for flag in mention.row_flags:
                name = BARE_FLAG.match(flag).group(1)
                if name not in node.flags:
                    problems.append(f"{mention.where()}\n    `{name}` isn't an option of `octapass {' '.join(node.path)}`")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_every_bare_flag_belongs_to_some_command(self):
        known = set().union(*(command.flags for command in self.tree.values()))
        unknown = [m.where() for m in self.flags if BARE_FLAG.match(m.text).group(1) not in known]
        self.assertEqual(unknown, [], "\n" + "\n".join(unknown))

    def test_every_command_of_the_cli_is_in_the_skill(self):
        # A new command (an organisation's, say) fails here until the skill says how to use it.
        reached = set()
        for _, words in self.commands:
            node, _ = check(self.tree, words)
            path = node.path
            while path:
                reached.add(path)
                path = path[:-1]
        missing = sorted(" ".join(path) for path in self.tree if path and path not in reached)
        self.assertEqual(missing, [], "Add these to references/commands.md: " + ", ".join(f"octapass {m}" for m in missing))


class SkillAgainstTheSource(unittest.TestCase):
    """Reads the CLI's source, so it needs no build."""

    def test_environment_variables_exist(self):
        sources = [REPO / "apps/cli/src", REPO / "apps/desktop/crates/connect/src"]
        code = "\n".join(p.read_text(encoding="utf-8") for root in sources for p in root.rglob("*.rs"))
        named = set(re.findall(r"\bOCTAPASS_[A-Z][A-Z0-9_]*\b", skill_text()))
        self.assertTrue({"OCTAPASS_SERVICE_ACCOUNT_TOKEN", "OCTAPASS_NO_DESKTOP"} <= named)
        missing = sorted(name for name in named if f'"{name}"' not in code)
        self.assertEqual(missing, [], "The CLI doesn't read these: " + ", ".join(missing))

    def test_exit_codes_match_error_rs(self):
        source = (REPO / "apps/cli/src/error.rs").read_text(encoding="utf-8")
        codes = {int(n) for n in re.findall(r"^\s+\w+ = (\d+),", source, re.M)}
        self.assertEqual(codes, set(range(9)))
        table = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        documented = {int(n) for n in re.findall(r"^\| (\d+) \|", table, re.M)}
        self.assertTrue(codes <= documented, f"SKILL.md's exit codes leave out {sorted(codes - documented)}")

    def test_front_matter_follows_the_agent_skills_format(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"^---\nname: (.+)\ndescription: (.+)\n---\n", text)
        self.assertIsNotNone(match)
        name, description = match.groups()
        self.assertEqual(name, SKILL.name)
        self.assertRegex(name, r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertLessEqual(len(description), 1024)

    def test_links_between_the_files_resolve(self):
        for file in FILES:
            for target in re.findall(r"\]\(([^)#:]+\.md)(?:#[^)]*)?\)", file.read_text(encoding="utf-8")):
                self.assertTrue((file.parent / target).exists(), f"{file.name} links to {target}")

    def test_safety_rules_stay(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        for rule in ("Don't print secrets", "Inject secrets", "Never handle the master password or Secret Key", "Confirm before"):
            self.assertIn(rule, text)


HELP = """Make a thing

Usage: octapass thing [OPTIONS] <FORMAT> [FILE]

Arguments:
  <FORMAT>
          Possible values:
          - csv:  Comma separated
          - json

  [FILE]  Default: stdin

Options:
  -o, --output <FILE>   Write here
      --shape <SHAPE>   [default: a] [possible values: a, b]
      --force           Replace it
  -n                    No newline
  -h, --help            Print help
"""


class Parser(unittest.TestCase):
    """The readers themselves, on fixed text."""

    def setUp(self):
        root = Command(())
        root.children = {"thing": None}
        root.flags = {"--json": False}
        self.tree = {(): root, ("thing",): parse_help(HELP, ("thing",))}

    def test_help_is_read(self):
        thing = self.tree[("thing",)]
        self.assertEqual(thing.flags, {"-o": True, "--output": True, "--shape": True, "--force": False, "-n": False, "-h": False, "--help": False})
        self.assertEqual(thing.values["--shape"], {"a", "b"})
        self.assertEqual(thing.positional_values, [{"csv", "json"}, None])

    def test_commands_and_subcommands_are_read(self):
        page = "Top\n\nUsage: octapass [OPTIONS] <COMMAND>\n\nCommands:\n  env     Environments\n  service-account  Accounts\n  help    Print this\n\nOptions:\n      --json  JSON\n"
        self.assertEqual(list(parse_help(page).children), ["env", "service-account"])

    def test_good_commands_pass(self):
        for words in (["thing", "csv", "-o", "out", "--force"], ["--json", "thing", "json", "--shape=b"], ["thing", "PLACEHOLDER", "-n"]):
            self.assertEqual(check(self.tree, words)[1], [], words)

    def test_unknown_flags_commands_and_values_fail(self):
        self.assertIn("`--forse`", check(self.tree, ["thing", "csv", "--forse"])[1][0])
        self.assertIn("`thang`", check(self.tree, ["thang"])[1][0])
        self.assertIn("`--shape c`", check(self.tree, ["thing", "csv", "--shape", "c"])[1][0])
        self.assertIn("`xml`", check(self.tree, ["thing", "xml"])[1][0])

    def test_words_after_double_dash_belong_to_the_command(self):
        self.assertEqual(check(self.tree, ["thing", "csv", "--", "npm", "--whatever"])[1], [])

    def test_shell_lines_are_cut_at_operators(self):
        self.assertEqual(invocations('printf x | octapass --json thing csv > out.txt # note'), [["--json", "thing", "csv"]])
        self.assertEqual(invocations('eval "$(octapass env hook zsh)"'), [["env", "hook", "zsh"]])
        self.assertEqual(invocations("octapass read octapass://<vault>/<item>/<field> -n"), [["read", "octapass://PLACEHOLDER/PLACEHOLDER/PLACEHOLDER", "-n"]])
        self.assertEqual(invocations('KEY="octapass://A/b c/d" octapass run -- ./x.sh'), [["run", "--", "./x.sh"]])
        self.assertEqual(invocations("octapass.toml and git-credential-octapass"), [])


if __name__ == "__main__":
    unittest.main()
