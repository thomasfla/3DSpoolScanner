package com.example.a3dspoolscanner
import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Card
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.a3dspoolscanner.ui.theme._3DSpoolScannerTheme
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.nfc.tech.MifareClassic
import androidx.compose.material3.Scaffold
import androidx.compose.ui.graphics.toArgb

class MainActivity : ComponentActivity() {
    private var nfcAdapter: NfcAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Initialize NFC adapter
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

        setContent {
            _3DSpoolScannerTheme {
                val scannedTag = remember { mutableStateOf("Ready to scan an NFC tag.") }

                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        message = scannedTag.value,
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()

        // Enable NFC foreground dispatch
        val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_MUTABLE
        )
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, null)
    }

    override fun onPause() {
        super.onPause()
        // Disable NFC foreground dispatch
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TAG_DISCOVERED == intent.action) {
            val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            if (tag != null) {
                handleNfcTag(tag)
            }
        }
    }

    private fun handleNfcTag(tag: Tag) {
        val uid = tag.id.joinToString("") { String.format("%02X", it) }

        // Master key for deriving keys
        val masterKey = byteArrayOf(
            0x9a.toByte(), 0x75.toByte(), 0x9c.toByte(), 0xf2.toByte(),
            0xc4.toByte(), 0xf7.toByte(), 0xca.toByte(), 0xff.toByte(),
            0x22.toByte(), 0x2c.toByte(), 0xb9.toByte(), 0x76.toByte(),
            0x9b.toByte(), 0x41.toByte(), 0xbc.toByte(), 0x96.toByte()
        )

        val info = byteArrayOf(
            'R'.code.toByte(), 'F'.code.toByte(), 'I'.code.toByte(), 'D'.code.toByte(),
            '-'.code.toByte(), 'A'.code.toByte(), 0x00
        )

        // Derive keys using HKDF
        val totalOutputLength = 16 * 6
        val hkdfOutput = hkdf(
            inputKeyMaterial = tag.id,
            totalOutputLength = totalOutputLength,
            salt = masterKey,
            info = info
        )

        val derivedKeys = hkdfOutput.asList().chunked(6).map { it.toByteArray() }

        // Read Blocks 4 and 5
        val (filamentName, filamentColor) = readMifareClassicBlocks(tag, derivedKeys)

        // Update UI with the parsed data
        setContent {
            _3DSpoolScannerTheme {
                SpoolInfoCard(
                    uid = uid,
                    filamentName = filamentName,
                    filamentColor = filamentColor
                )
            }
        }
    }
}

@Composable
fun SpoolInfoCard(
    uid: String,
    filamentName: String,
    filamentColor: Int
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp) // General padding
    ) {
        Spacer(modifier = Modifier.height(32.dp)) // Add top clearance

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(text = "Tag UID: $uid")
                Text(text = "Filament Name: $filamentName")
                Spacer(modifier = Modifier.height(8.dp))
                Text(text = "Filament Color:")
                Box(
                    modifier = Modifier
                        .size(50.dp)
                        .background(Color(filamentColor))
                )
            }
        }
    }
}


@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    _3DSpoolScannerTheme {
        SpoolInfoCard(
            uid = "12345678",
            filamentName = "PLA",
            filamentColor = Color.Red.toArgb()
        )
    }
}

private fun readMifareClassicBlocks(tag: Tag, keys: List<ByteArray>): Pair<String, Int> {
    val mifare = MifareClassic.get(tag)
    return try {
        mifare.connect()

        val sectorIndex = 1 // Sector containing Blocks 4 and 5
        val startBlock = mifare.sectorToBlock(sectorIndex)
        var authenticated = false

        // Authenticate Sector 1
        for (key in keys) {
            if (mifare.authenticateSectorWithKeyA(sectorIndex, key) || mifare.authenticateSectorWithKeyB(sectorIndex, key)) {
                authenticated = true
                break
            }
        }

        if (authenticated) {
            // Read Blocks 4 and 5
            val block4 = mifare.readBlock(startBlock)
            val block5 = mifare.readBlock(startBlock + 1)

            // Parse filament name and color
            parseBlock4And5(block4, block5)
        } else {
            "Authentication Failed" to Color.Black.toArgb()
        }
    } catch (e: Exception) {
        "Error reading tag" to Color.Black.toArgb()
    } finally {
        try {
            mifare.close()
        } catch (ignored: Exception) {
        }
    }
}

private fun parseBlock4And5(block4: ByteArray, block5: ByteArray): Pair<String, Int> {
    return try {
        // Filament name from Block 4
        val filamentName = block4.toString(Charsets.US_ASCII).trim()

        // Extract RGBA from Block 5
        val r = block5[0].toInt() and 0xFF
        val g = block5[1].toInt() and 0xFF
        val b = block5[2].toInt() and 0xFF
        val a = block5[3].toInt() and 0xFF
        val color = (a shl 24) or (r shl 16) or (g shl 8) or b

        filamentName to color
    } catch (e: Exception) {
        "Unknown" to Color.Black.toArgb()
    }
}

fun hkdf(
    inputKeyMaterial: ByteArray,
    totalOutputLength: Int,
    salt: ByteArray,
    hashAlgorithm: String = "HmacSHA256",
    info: ByteArray = ByteArray(0)
): ByteArray {
    val mac = Mac.getInstance(hashAlgorithm)
    mac.init(SecretKeySpec(salt, hashAlgorithm))
    val prk = mac.doFinal(inputKeyMaterial)

    mac.init(SecretKeySpec(prk, hashAlgorithm))
    val result = ByteArray(totalOutputLength)
    var t = ByteArray(0)
    var generatedBytes = 0
    var blockIndex = 1.toByte()

    while (generatedBytes < totalOutputLength) {
        mac.update(t)
        mac.update(info)
        mac.update(blockIndex)
        t = mac.doFinal()
        val toCopy = t.size.coerceAtMost(totalOutputLength - generatedBytes)
        System.arraycopy(t, 0, result, generatedBytes, toCopy)
        generatedBytes += toCopy
        blockIndex++
    }
    return result
}

@Composable
fun Greeting(message: String, modifier: Modifier = Modifier) {
    Text(
        text = message,
        modifier = modifier
    )
}