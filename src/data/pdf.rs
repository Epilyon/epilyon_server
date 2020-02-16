/*
 * Epilyon, keeping EPITA students organized
 * Copyright (C) 2019-2020 Adrien 'Litarvan' Navratil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::collections::btree_map::BTreeMap;
use std::cmp::Ordering;

use lopdf::{Document, Object};
use lopdf::content::Content;
use failure::Fail;

// This is not perfect, but it works. I had to go through a part of the PDF spec for this...
pub fn parse_qcm(data: &[u8]) -> Result<Vec<f32>, PDFError> {
    let doc = Document::load_mem(data)?;
    let page_id = doc.page_iter().nth(0)
        .ok_or(lopdf::Error::PageNumberNotFound(0))?;

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

                let xobj = operands.get(0).ok_or(PDFError::MalformedQCM)?;
                let yobj = operands.get(1).ok_or(PDFError::MalformedQCM)?;

                x = x + (xobj.as_f64().or_else(|_| xobj.as_i64().map(|i| i as f64))? * sx);
                y = y + (yobj.as_f64().or_else(|_| yobj.as_i64().map(|i| i as f64))? * sy);

                line = false; // We are starting a new line, so setting line to false
            },
            "Tf" => {
                // Sets the current font

                let current_font = operands[0].as_name()?;
                current_encoding = encodings.get(current_font).map(std::string::String::as_str);
            }
            "Tj" => {
                // Adds text to the current line

                for operand in operands {
                    if let Object::String(ref bytes, _) = *operand {
                        let decoded_text = Document::decode_text(current_encoding, bytes);

                        if decoded_text.contains(" ") {
                            // In some QCM there is the user name at the top, we must not touch it
                            continue;
                        }

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

                let n = operands.get(0).ok_or(PDFError::MalformedQCM)?;
                if n.as_f64().is_err() {
                    sx = n.as_i64()? as f64;
                } else {
                    sx = n.as_f64()?;
                }
                
                let n = operands.get(3).ok_or(PDFError::MalformedQCM)?;
                if n.as_f64().is_err() {
                    sy = n.as_i64()? as f64;
                } else {
                    sy = n.as_f64()?;
                }

                x = operands.get(4).ok_or(PDFError::MalformedQCM)?.as_f64()?;
                y = operands.get(5).ok_or(PDFError::MalformedQCM)?.as_f64()?;

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

    let mut grades: Vec<f32> = Vec::new();
    for e in result {
        grades.push(e.text.parse::<f32>().map_err(|_| PDFError::MalformedQCM)?);
    }

    Ok(grades)
}

#[derive(Debug)]
struct Entry {
    x: f64,
    y: f64,
    text: String
}

#[derive(Fail, Debug)]
pub enum PDFError {
    #[fail(display = "PDF Parsing error : {}", error)]
    ParsingError {
        error: lopdf::Error
    },

    #[fail(display = "Malformed PDF, unexcepted operand count or value type")]
    MalformedQCM
}

from_error!(lopdf::Error, PDFError, PDFError::ParsingError);
