use lopdf::{Document, Object};
use lopdf::content::Content;
use std::collections::btree_map::BTreeMap;
use std::cmp::Ordering;

// This is not perfect, but it works. I had to go through a part of the PDF spec for this...
pub fn parse_qcm(data: &[u8]) -> Result<Vec<f32>, lopdf::Error> {
    let doc = Document::load_mem(data)?;

    let page_opt = doc.page_iter().nth(0);
    if page_opt.is_none() {
        return Err(lopdf::Error::PageNumberNotFound(0))
    }

    let page_id = page_opt.unwrap();
    let encodings = doc
        .get_page_fonts(page_id)
        .into_iter()
        .map(|(name, font)| (name, font.get_font_encoding().to_owned()))
        .collect::<BTreeMap<Vec<u8>, String>>();

    let content_data = doc.get_page_content(page_id)?;
    let content = Content::decode(&content_data)?;
    let mut current_encoding = None;

    // Our simplified text matrix
    let mut x = 0f64;
    let mut y = 0f64;
    let mut sx = 1f64; // Scale X
    let mut sy = 1f64; // Scale Y

    let mut result: Vec<Entry> = Vec::new();
    let mut line = false; // False if we are starting a new line, true if we are staying on the same one

    for operation in &content.operations {
        let operands = &operation.operands;

        match operation.operator.as_ref() {
            "BT" => {
                // Starts a new text block

                x = 0f64;
                y = 0f64;
            },
            "Td" => {
                // Starts a new line at x, y

                x = x + (operands.get(0).unwrap().as_f64().unwrap() * sx);
                y = y + (operands.get(1).unwrap().as_f64().unwrap() * sy);

                line = false; // We are starting a new line, so setting line to false
            },
            "Tf" => {
                // Sets the current font

                let current_font = operands[0].as_name().unwrap();
                current_encoding = encodings.get(current_font).map(std::string::String::as_str);
            }
            "Tj" => {
                // Adds text to the current line

                for operand in operands {
                    if let Object::String(ref bytes, _) = *operand {
                        let decoded_text = Document::decode_text(current_encoding, bytes);

                        if line {
                            // Means that text is being written on the same line, so we add an offset
                            // (because text is drawn next to the previous one)
                            x = x + 10f64;
                        }

                        result.push(Entry { x, y, text: decoded_text });

                        // We started drawing on the line, so we set line to true to make the next one
                        // add an offset, but only if we didn't start drawing on a new line in between
                        line = true;
                    }
                }
            },
            "Tm" => {
                // Defines a new text matrix (x, y, scalex, scaley), and also starts a new line

                let n = operands.get(0).unwrap();
                if n.as_f64().is_err() {
                    sx = n.as_i64().unwrap() as f64;
                } else {
                    sx = n.as_f64().unwrap();
                }
                
                let n = operands.get(3).unwrap();
                if n.as_f64().is_err() {
                    sy = n.as_i64().unwrap() as f64;
                } else {
                    sy = n.as_f64().unwrap();
                }

                x = operands.get(4).unwrap().as_f64().unwrap();
                y = operands.get(5).unwrap().as_f64().unwrap();

                line = false; // We are starting a new line, so setting line to false
            }
            _ => {}
        }
    }

    // Sorting the results first by X, then by Y, with a margin for both (because the matrix is simplified,
    // the shear is not applied, so there might be a small margin between text on the same row/column)
    result.sort_by(|a, b| {
        if (a.x - b.x).abs() < 12f64 {
            if (a.y - b.y).abs() < 10f64 {
                Ordering::Equal
            } else if a.y < b.y {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        } else if a.x > b.x {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    });

    Ok(result.iter().map(|e| e.text.parse::<f32>().unwrap()).collect())
}

#[derive(Debug)]
struct Entry {
    x: f64,
    y: f64,
    text: String
}