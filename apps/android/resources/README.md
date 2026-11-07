# Octa Pass Android resources

Strings (English and Arabic) and design tokens for the Android app, generated from the web vault's catalogs and `packages/ui`'s tokens by [`tools/native-resources`](../../../tools/native-resources/README.md). Don't edit these files: change the sources and run `node tools/native-resources/generate.mjs`.

| Path | |
|---|---|
| `src/main/res/values/strings.xml`, `src/main/res/values-ar/strings.xml` | `R.string.common_back`, `R.plurals.list_searchPlaceholder` |
| `src/main/kotlin/app/octapass/resources/Tokens.kt` | `Tokens.LightColors.trust`, `Tokens.TypeScale.md`, … as plain constants |

`build.gradle.kts` makes this folder the `:resources` library of [`apps/android`](../README.md) (`namespace = "app.octap.resources"`); the app depends on it.
