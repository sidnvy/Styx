package com.styx.host

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The Rust credential blob is opaque here and is never written as plaintext. */
class CredentialStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "styx-credentials"))
    private val alias = "styx-host-credentials"
    fun exists(): Boolean = file.baseFile.exists()

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build())
        }.generateKey()
    }

    @Synchronized fun load(): String? {
        if (!exists()) return null
        val envelope = JSONObject(file.openRead().bufferedReader().use { it.readText() })
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, Base64.decode(envelope.getString("iv"), Base64.NO_WRAP)))
        return cipher.doFinal(Base64.decode(envelope.getString("data"), Base64.NO_WRAP)).toString(Charsets.UTF_8)
    }

    @Synchronized fun forget() {
        file.delete()
        check(!exists())
    }

    @Synchronized fun store(json: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val envelope = JSONObject()
            .put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .put("data", Base64.encodeToString(cipher.doFinal(json.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP))
        val output = file.startWrite()
        try {
            output.write(envelope.toString().toByteArray(Charsets.UTF_8))
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }
}
