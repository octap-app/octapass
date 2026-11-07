// `octapass://<vault>/<item>/<field>` references for what GET /v1/items lists.

package app.octap.connect

data class FieldRow(
    val vault: String,
    val item: String,
    val itemId: String,
    val field: String,
    val secret: Boolean,
    val reference: String,
)

/** `%` as `%25` and `/` as `%2F`, in that order so the second isn't encoded twice. */
fun encodePart(part: String): String = part.replace("%", "%25").replace("/", "%2F")

fun reference(vault: String, item: String, field: String): String =
    "octapass://${encodePart(vault)}/${encodePart(item)}/${encodePart(field)}"

private fun nameKey(vault: String, item: String) = vault.trim().lowercase() to item.trim().lowercase()

/**
 * One row per field that a reference can name. Item names are matched without regard to case and
 * two items with the same name would make a reference ambiguous, so those are named by id. So is
 * an item with no name. A blank field name can't be written in a reference, so it's left out.
 */
fun fieldRows(items: List<ItemRef>): List<FieldRow> {
    val seen = items.groupingBy { nameKey(it.vault, it.item) }.eachCount()
    return items.flatMap { item ->
        val named = item.item.isNotBlank()
        val unique = named && seen[nameKey(item.vault, item.item)] == 1
        item.fields.filter { it.name.isNotBlank() }.map { field ->
            FieldRow(
                vault = item.vault,
                item = if (named) item.item else item.itemId,
                itemId = item.itemId,
                field = field.name,
                secret = field.secret,
                reference = reference(item.vault, if (unique) item.item else item.itemId, field.name),
            )
        }
    }
}
