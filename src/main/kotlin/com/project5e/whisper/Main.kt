package com.project5e.whisper

import com.project5e.whisper.legacy.IDObfuscation
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonConfiguration
import kotlinx.serialization.json.content
import kotlinx.serialization.json.int
import org.jline.builtins.ConfigurationPath
import org.jline.console.*
import org.jline.console.impl.JlineCommandRegistry
import org.jline.console.impl.SystemRegistryImpl
import org.jline.reader.EndOfFileException
import org.jline.reader.LineReader
import org.jline.reader.LineReaderBuilder
import org.jline.reader.UserInterruptException
import org.jline.reader.impl.DefaultParser
import org.jline.terminal.TerminalBuilder
import org.jline.utils.AttributedString
import org.jline.widget.AutosuggestionWidgets
import org.jline.widget.TailTipWidgets
import org.jline.widget.TailTipWidgets.TipType
import java.io.File
import java.nio.file.Path
import java.nio.file.Paths
import java.util.*
import java.util.function.Supplier
import javax.crypto.AEADBadTagException
import javax.crypto.SecretKey


object Main {
    private val json = Json(JsonConfiguration.Stable)
    private val workDir = Paths.get(System.getProperty("user.dir"))

    private val terminal = TerminalBuilder.builder().jna(true).build()
    private val parser = DefaultParser()
    private val file = File(Main::class.java.protectionDomain.codeSource.location.toURI().path)
    private val root = file.canonicalPath.replace("classes", "").replace("\\\\", "/")
    private val configPath = ConfigurationPath(Paths.get(root), Paths.get(root))
    private val wCommands = WCommands()
    private val systemRegistry = SystemRegistryImpl(parser, terminal, Supplier { workDir }, configPath).apply {
        setCommandRegistries(wCommands)
    }
    private val reader = LineReaderBuilder.builder()
            .terminal(terminal)
            .parser(parser)
            .completer(systemRegistry.completer())
            .build()
            .also {
                wCommands.reader = it
                wCommands.path = workDir
            }

    @JvmStatic
    fun main(args: Array<String>) {
        //val autosuggestionWidgets = AutosuggestionWidgets(reader).also { it.enable() }
        val tailTips: Map<String, CmdDesc> = mapOf(
            "loadkeys" to CmdDesc(listOf(AttributedString("loadkeys [path]")), listOf(), mapOf()),
            "selectkey" to CmdDesc(listOf(AttributedString("selectkey [key name]")), listOf(), mapOf()),
            "obfuscate" to CmdDesc(listOf(AttributedString("obfuscate [int value]")), listOf(), mapOf()),
            "restore" to CmdDesc(listOf(AttributedString("restore [obfuscated string]")), listOf(), mapOf())
        )
        val tailTipWidgets = TailTipWidgets(reader, tailTips, 1, TipType.COMPLETER)
        tailTipWidgets.enable()

        while (true) {
            try {
                systemRegistry.cleanUp()
                val line = reader.readLine("whisper> ")
                systemRegistry.execute(line)
            } catch (_: UserInterruptException) {
            } catch (e: EndOfFileException) {
                break
            } catch (e: Exception) {
                systemRegistry.trace(e)
            }
        }
    }

    class WCommands: JlineCommandRegistry(), CommandRegistry {
        lateinit var reader: LineReader
        lateinit var path: Path
        private val keys: MutableMap<String, SecretKey> = mutableMapOf()
        private val obfuscators: MutableMap<String, Obfuscator?> = mutableMapOf()
        private val legacyKeys: MutableMap<String, Int> = mutableMapOf()
        private val legacyObfuscators: MutableMap<String, IDObfuscation?> = mutableMapOf()
        private var activeKey: String? = null
        private var legacy: Boolean = false
        private val commands = mapOf(
            "pwd" to CommandMethods({ it.println(path) }, this::defaultCompleter),
            "loadkeys" to CommandMethods(this::loadKeys, this::defaultCompleter),
            "listkeys" to CommandMethods(this::listKeys, this::defaultCompleter),
            "selectkey" to CommandMethods(this::selectKey, this::defaultCompleter),
            "legacy" to CommandMethods({
                legacy = !legacy
                if (legacy) it.println("legacy mode enabled")
                else it.println("legacy mode disabled")
            }, this::defaultCompleter),
            "obfuscate" to CommandMethods(this::obfuscate, this::defaultCompleter),
            "restore" to CommandMethods(this::restore, this::defaultCompleter)
        )

        init {
            registerCommands(commands)
        }

        override fun commandInfo(command: String): List<String> {
            return if (command == "help") {
                commands.keys.sorted().toList()
            } else {
                when (command) {
                    "legacy" -> listOf("Toggle legacy mode")
                    "listkeys" -> listOf("list loaded keys")
                    "loadkeys" -> listOf("load keys from json")
                    "obfuscate" -> listOf("obfuscate a int")
                    "pwd" -> listOf("print current working directory")
                    "restore" -> listOf("restore a obfuscated string")
                    "selectkey" -> listOf("select a key to use")
                    else -> listOf("Unknown Command")
                }
            }
        }

        private fun loadKeys(input: CommandInput) {
            if (input.args().isEmpty()) return input.eprintln("Invalid args, Usage loadkeys <filename>")
            val filename = input.args()[0]
            val file = Paths.get(path.toAbsolutePath().toString(), filename).toFile()
            val keyJson = json.parseJson(file.readText()).jsonObject
            keyJson.getObject("keys").forEach { name, key ->
                keys[name] = key.content.fromBase64().toKey("AES")
            }
            keyJson.getObject("legacy").forEach { name, key -> legacyKeys[name] = key.int }
            input.println("Load ${keys.size} keys and ${legacyKeys.size} legacy keys from $filename")
        }

        private fun listKeys(input: CommandInput) {
            input.println("name         algorithm    signature   legacy")
            input.println("-------------------------------------------")
            keys.forEach { (name, key) ->
                input.println(
                    name.padEnd(13) +
                            key.algorithm.padEnd(13) +
                            key.encoded.sha256().hex.slice(0 until 8).padEnd(12) +
                            (legacyKeys[name]?.toString() ?: "null")
                )
            }
        }

        private fun obfuscate(input: CommandInput) {
            val id: Long
            if (input.args().isEmpty()) return input.eprintln("Invalid args, Usage obfuscate <id: Long>")
            if (activeKey == null) return input.eprintln("No active key, select key first")
            try {
                id = input.args()[0].toLong()
            } catch (_: NumberFormatException) {
                return input.eprintln("Invalid number format, Usage obfuscate <id: Long>")
            }
            if (legacy) {
                val obfuscator = legacyObfuscators.computeIfAbsent(activeKey!!) { keyName ->
                    IDObfuscation(legacyKeys[keyName]!!)
                }!!
                input.println(obfuscator.obfuscate(id))
                return
            }
            val obfuscator = obfuscators.computeIfAbsent(activeKey!!) { keyName ->
                Crypto.getAes128ECBHmacSHA1Instance(keys[keyName]!!).let { Obfuscator.createInstance(it) }
            }!!
            input.println(obfuscator.obfuscate(id))
        }

        private fun restore(input: CommandInput) {
            if (input.args().isEmpty()) return input.eprintln("Invalid args, Usage obfuscate <id: Long>")
            if (activeKey == null) return input.eprintln("No active key, select key first")
            val id: String = input.args()[0]

            try {
                if (legacy) {
                    val obfuscator = legacyObfuscators.computeIfAbsent(activeKey!!) { keyName ->
                        IDObfuscation(legacyKeys[keyName]!!)
                    }!!
                    input.println(obfuscator.restore(id))
                } else {
                    val obfuscator = obfuscators.computeIfAbsent(activeKey!!) { keyName ->
                        Crypto.getAes128ECBHmacSHA1Instance(keys[keyName]!!).let { Obfuscator.createInstance(it) }
                    }!!
                    input.println(obfuscator.restore(id))
                }
            } catch (_: AEADBadTagException) {
                input.eprintln("Bad signature")
            } catch (_: Throwable) {
                input.eprintln("Bad string format")
            }
        }

        private fun selectKey(input: CommandInput) {
            if (input.args().isEmpty()) return input.println("active key: $activeKey")
            val key = input.args()[0]
            if (keys.containsKey(key)) {
                activeKey = key
                input.println("active key: $activeKey")
            } else {
                input.eprintln("ERROR: Key <$key> not exist")
            }
        }

        private inline fun <reified T : Any> CommandInput.println(x: T) = terminal().writer().println(x)
        private inline fun <reified T : Any> CommandInput.eprintln(x: T) = err().println(x)
    }
}