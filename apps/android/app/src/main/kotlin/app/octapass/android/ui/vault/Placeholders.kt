package app.octap.android.ui.vault

import app.octap.vault.maskedEmailProviders

private val providers by lazy { maskedEmailProviders() }

/** A masked email provider's name, as the web vault shows it (`providerName`). */
fun providerName(id: String?): String = providers.firstOrNull { it.id == id }?.name ?: id.orEmpty()
