//! JSON tree flattener — Rust port of `lib/flattening/flatten.go`.
//!
//! Flattens an arbitrary JSON object into a list of `(key, value)` pairs whose
//! keys are dot-and-bracket paths the subject-mapping engine can match against
//! `.properties.clearance`, `.properties.levels[]`, `.properties.country[0]`, etc.
//!
//! Reference: <https://pkg.go.dev/github.com/opentdf/platform/lib/flattening>

use serde_json::Value as JsonValue;
use thiserror::Error;

/// Item produced by the flattener.
#[derive(Debug, Clone)]
pub struct FlattenedItem {
    pub key: String,
    pub value: JsonValue,
}

/// Flattened JSON document.
#[derive(Debug, Clone, Default)]
pub struct Flattened {
    pub items: Vec<FlattenedItem>,
}

#[derive(Debug, Error, Clone)]
pub enum FlattenError {
    #[error("unrecognized item in json (null is not supported)")]
    UnsupportedNull,
}

/// Flatten a JSON object into key paths matching the Go implementation.
pub fn flatten(value: &JsonValue) -> Result<Flattened, FlattenError> {
    let items = flatten_value(value)?;
    Ok(Flattened { items })
}

fn flatten_value(value: &JsonValue) -> Result<Vec<FlattenedItem>, FlattenError> {
    let mut out = Vec::new();
    match value {
        JsonValue::Object(map) => {
            for (k, v) in map {
                let nested = flatten_value(v)?;
                for item in nested {
                    out.push(FlattenedItem {
                        key: format!(".{k}{}", item.key),
                        value: item.value,
                    });
                }
            }
        }
        JsonValue::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                let indexed_key = format!("[{idx}]");
                let bracketless_key = "[]".to_string();
                let nested = flatten_value(item)?;
                for n in nested {
                    out.push(FlattenedItem {
                        key: format!("{indexed_key}{}", n.key),
                        value: n.value.clone(),
                    });
                    out.push(FlattenedItem {
                        key: format!("{bracketless_key}{}", n.key),
                        value: n.value,
                    });
                }
            }
        }
        JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
            out.push(FlattenedItem {
                key: String::new(),
                value: value.clone(),
            });
        }
        JsonValue::Null => {
            return Err(FlattenError::UnsupportedNull);
        }
    }
    Ok(out)
}

/// Look up every flattened value whose key exactly equals `selector`.
pub fn get_from_flattened<'a>(flat: &'a Flattened, selector: &str) -> Vec<&'a JsonValue> {
    flat.items
        .iter()
        .filter(|i| i.key == selector)
        .map(|i| &i.value)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flatten_simple_object() {
        let v = json!({"properties": {"clearance": "secret"}});
        let f = flatten(&v).unwrap();
        let keys: Vec<&str> = f.items.iter().map(|i| i.key.as_str()).collect();
        assert!(keys.contains(&".properties.clearance"));
    }

    #[test]
    fn flatten_array_emits_indexed_and_bracketless() {
        let v = json!({"properties": {"country": ["us", "uk"]}});
        let f = flatten(&v).unwrap();
        let keys: Vec<&str> = f.items.iter().map(|i| i.key.as_str()).collect();
        assert!(keys.contains(&".properties.country[]"));
        assert!(keys.contains(&".properties.country[0]"));
        assert!(keys.contains(&".properties.country[1]"));

        let vals_for_bracket = get_from_flattened(&f, ".properties.country[]");
        assert_eq!(vals_for_bracket.len(), 2);
    }

    #[test]
    fn flatten_nested_arrays() {
        let v = json!({"a": [{"b": 1}, {"b": 2}]});
        let f = flatten(&v).unwrap();
        // Want both .a[].b and .a[0].b / .a[1].b
        let bracket_b = get_from_flattened(&f, ".a[].b");
        assert_eq!(bracket_b.len(), 2);
    }
}
