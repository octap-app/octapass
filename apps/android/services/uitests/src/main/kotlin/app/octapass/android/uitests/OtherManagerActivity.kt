package app.octap.android.uitests

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.providerevents.IntentHandler
import androidx.credentials.providerevents.exception.ImportCredentialsNoExportOptionException
import androidx.credentials.providerevents.transfer.ImportCredentialsResponse

/**
 * Another password manager, as Octa Pass sees it in the credential transfer test: when Octa Pass
 * imports and the user picks this app, it hands over [CXF], a login and a card.
 */
class OtherManagerActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = IntentHandler.retrieveProviderImportCredentialsRequest(intent)
        if (request == null || request.credId != ENTRY_ID) {
            IntentHandler.setImportCredentialsException(intent, ImportCredentialsNoExportOptionException("unknown entry"))
        } else {
            IntentHandler.setImportCredentialsResponse(this, request.uri, intent, ImportCredentialsResponse(CXF))
        }
        setResult(RESULT_OK, intent)
        finish()
    }

    companion object {
        const val ENTRY_ID = "octa-pass-ui-tests"
        const val ACCOUNT = "Other manager"
        const val LOGIN = "Transfer test"

        val CXF = """
            {"version":{"major":1,"minor":0},"exporterRpId":"app.octap.android.test","exporterDisplayName":"$ACCOUNT",
             "timestamp":1792800000,"accounts":[{"id":"dGVzdA","username":"","email":"grace@example.com","items":[
              {"id":"MQ","title":"$LOGIN","scope":{"urls":["https://transfer.example"],"androidApps":[]},
               "credentials":[{"type":"basic-auth","username":{"fieldType":"string","value":"grace"},
                               "password":{"fieldType":"concealed-string","value":"moved-over-1"}}]},
              {"id":"Mg","title":"Travel card","credentials":[{"type":"credit-card",
               "number":{"fieldType":"string","value":"4111111111111111"},"fullName":{"fieldType":"string","value":"Grace Hopper"}}]}]}]}
        """.trimIndent()
    }
}
