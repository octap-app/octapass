//! A CSV file whose first row names the columns.
//!
//! Parsers claim the columns they understand with [`CsvTable::take`]; every other non-empty cell
//! is handed back by [`CsvTable::extras`], so unknown columns become custom fields or note lines
//! instead of being dropped.

use super::ImportError;
use crate::error::Error;

pub(super) struct CsvTable {
    /// Header names as written in the file.
    pub headers: Vec<String>,
    normalized: Vec<String>,
    used: Vec<bool>,
    pub rows: Vec<Row>,
}

pub(super) struct Row {
    /// The file line the row starts on, for warnings.
    pub line: u64,
    cells: Vec<String>,
}

impl CsvTable {
    pub fn parse(text: &str, delimiter: u8) -> Result<Self, ImportError> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .delimiter(delimiter)
            .from_reader(text.as_bytes());
        let mut records = reader.records();
        let header = match records.next() {
            Some(Ok(header)) => header,
            Some(Err(_)) => return Err(invalid("The file isn't valid CSV.")),
            None => return Err(invalid("The file is empty.")),
        };
        let headers: Vec<String> = header.iter().map(|h| h.trim().to_string()).collect();
        let mut rows = Vec::new();
        for record in records {
            let record = record.map_err(|_| invalid("The file isn't valid CSV."))?;
            if record.iter().all(|cell| cell.trim().is_empty()) {
                continue;
            }
            rows.push(Row {
                line: record.position().map_or(0, |p| p.line()),
                cells: record.iter().map(str::to_string).collect(),
            });
        }
        Ok(Self {
            normalized: headers.iter().map(|h| normalize(h)).collect(),
            used: vec![false; headers.len()],
            headers,
            rows,
        })
    }

    /// The first column named any of `names` (compared case-insensitively, with spaces and dashes
    /// read as underscores), marked as used.
    pub fn take(&mut self, names: &[&str]) -> Option<usize> {
        let index = names
            .iter()
            .find_map(|name| self.normalized.iter().position(|h| h == &normalize(name)))?;
        self.used[index] = true;
        Some(index)
    }

    /// Like [`take`](Self::take) for a column given by its exact header (a user's mapping).
    pub fn take_exact(&mut self, header: &str) -> Option<usize> {
        let index = self.headers.iter().position(|h| h == header.trim())?;
        self.used[index] = true;
        Some(index)
    }

    /// Marks metadata columns (ids, timestamps) as handled without reading them.
    pub fn ignore(&mut self, names: &[&str]) {
        for name in names {
            self.take(&[name]);
        }
    }

    pub fn has(&self, names: &[&str]) -> bool {
        names
            .iter()
            .any(|name| self.normalized.contains(&normalize(name)))
    }

    /// `(header, value)` for every unclaimed, non-empty cell of a row.
    pub fn extras(&self, row: &Row) -> Vec<(String, String)> {
        row.cells
            .iter()
            .enumerate()
            .filter(|(i, cell)| {
                !self.used.get(*i).copied().unwrap_or(false) && !cell.trim().is_empty()
            })
            .map(|(i, cell)| {
                let header = self.headers.get(i).filter(|h| !h.is_empty());
                let label = header
                    .cloned()
                    .unwrap_or_else(|| format!("Column {}", i + 1));
                (label, cell.clone())
            })
            .collect()
    }
}

impl Row {
    pub fn get(&self, column: Option<usize>) -> Option<&str> {
        self.cells.get(column?).map(String::as_str)
    }

    pub fn cells(&self) -> &[String] {
        &self.cells
    }
}

fn normalize(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c == ' ' || c == '-' { '_' } else { c })
        .collect()
}

/// The delimiter of a CSV file: whichever of `,`, `;` and tab appears most in the header line.
pub(super) fn sniff_delimiter(text: &str) -> u8 {
    let header = text.lines().next().unwrap_or_default();
    b",;\t"
        .iter()
        .copied()
        .max_by_key(|&d| (header.bytes().filter(|&b| b == d).count(), d == b','))
        .unwrap_or(b',')
}

pub(super) fn invalid(detail: &'static str) -> ImportError {
    ImportError::new(Error::InvalidImportFile, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_newlines_and_unknown_columns() {
        let text = "Name,URL,Secret Question,\n\"A, \"\"quoted\"\" name\",https://a.com,\"multi\nline\",x\n,,,\n";
        let mut table = CsvTable::parse(text, b',').unwrap();
        let name = table.take(&["name"]);
        let url = table.take(&["url"]);
        assert_eq!(table.rows.len(), 1, "blank rows are dropped");
        let row = &table.rows[0];
        assert_eq!(row.get(name), Some("A, \"quoted\" name"));
        assert_eq!(row.get(url), Some("https://a.com"));
        assert_eq!(row.line, 2);
        assert_eq!(
            table.extras(row),
            [
                ("Secret Question".to_string(), "multi\nline".to_string()),
                ("Column 4".to_string(), "x".to_string())
            ]
        );
        assert_eq!(row.get(Some(9)), None);
    }

    #[test]
    fn header_names_are_forgiving() {
        let mut table = CsvTable::parse("Login-URI , User Name\n", b',').unwrap();
        assert!(table.has(&["login_uri"]));
        assert_eq!(table.take(&["user_name"]), Some(1));
        assert_eq!(table.take_exact("Login-URI"), Some(0));
        assert!(CsvTable::parse("", b',').is_err());
    }

    #[test]
    fn delimiters() {
        assert_eq!(sniff_delimiter("a;b;c\n1,2;3"), b';');
        assert_eq!(sniff_delimiter("a\tb\n"), b'\t');
        assert_eq!(sniff_delimiter("title\n"), b',');
    }
}
