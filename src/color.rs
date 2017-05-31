
use std::fmt;
use std::error::Error;
use std::io::{Write};

use termcolor::{Color, ColorChoice, ColorSpec, BufferWriter, WriteColor};

pub struct Printer {
    outwriter: BufferWriter,
    errwriter: BufferWriter
}

#[derive(Debug)]
pub struct FormatError(pub String);

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt("authentication error", f)
    }
}

impl Error for FormatError {
    fn description(&self) -> &str {
        "authentication error"
    }
}

pub fn build_spec(fg: Option<Color>, bold: bool) -> ColorSpec {
    let mut spec = ColorSpec::new();
    spec.set_fg(fg);
    // spec.set_bg(bg);
    spec.set_bold(bold);
    spec
}

impl Printer {
    pub fn new() -> Printer {
        Printer {
            outwriter: BufferWriter::stdout(ColorChoice::Always),
            errwriter: BufferWriter::stderr(ColorChoice::Always)
        }
    }

    #[allow(dead_code)]
    pub fn print_out(&self, fmtstr: &str, args: &Vec<(&str, &Option<ColorSpec>)>) -> Result<(), FormatError> {
        self.print(&self.outwriter, fmtstr, args, false)
    }

    pub fn println_out(&self, fmtstr: &str, args: &Vec<(&str, &Option<ColorSpec>)>) -> Result<(), FormatError> {
        self.print(&self.outwriter, fmtstr, args, true)
    }

    #[allow(dead_code)]
    pub fn print_err(&self, fmtstr: &str, args: &Vec<(&str, &Option<ColorSpec>)>) -> Result<(), FormatError> {
        self.print(&self.errwriter, fmtstr, args, false)
    }

    pub fn println_err(&self, fmtstr: &str, args: &Vec<(&str, &Option<ColorSpec>)>) -> Result<(), FormatError> {
        self.print(&self.errwriter, fmtstr, args, true)
    }


    fn print(&self, writer: &BufferWriter,
             fmtstr: &str, args: &Vec<(&str, &Option<ColorSpec>)>, newline: bool) -> Result<(), FormatError> {
        let mut buffer = writer.buffer();
        let mut arg_iter = args.iter();
        let mut char_iter = fmtstr.chars();
        let mut current = char_iter.next();
        let mut count = 0;
        while let Some(c) = current {
            match c {
                '{' => {
                    let c = char_iter.next();
                    match c {
                        Some('}') => {
                            if let Some(&(ref s, ref colorspec)) = arg_iter.next() {
                                if let &&Some(ref colorspec) = colorspec {
                                    buffer.set_color(colorspec).unwrap();
                                }
                                buffer.write(s.as_bytes()).unwrap();
                                if colorspec.is_some() {
                                    buffer.reset().unwrap();
                                }
                                count += 1;
                            } else {
                                return Err(FormatError(format!("Not enough arguments (need more than {})", count)));
                            }
                        }
                        Some('{') => {
                            buffer.write("{".as_bytes()).unwrap();
                        }
                        _ => {
                            return Err(FormatError(format!("{{ not closed")));
                        }
                    }
                },
                '}' => {
                    let c = char_iter.next();
                    match c {
                        Some('}') => {
                            buffer.write("}".as_bytes()).unwrap();
                        }
                        _ => {
                            return Err(FormatError(format!("}} not closed")));
                        }
                    }
                }
                c @ _ => {
                    let mut buf = [0; 4];
                    buffer.write(c.encode_utf8(&mut buf).as_bytes()).unwrap();
                }
            }
            current = char_iter.next();
        }
        if newline {
            buffer.write("\n".as_bytes()).unwrap();
        }
        writer.print(&buffer).unwrap();
        Ok(())
    }
}
