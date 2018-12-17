use std::io::Write;

use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

use util::StringError;

pub struct Printer {
    outwriter: BufferWriter,
    errwriter: BufferWriter,
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
            errwriter: BufferWriter::stderr(ColorChoice::Always),
        }
    }

    #[allow(dead_code)]
    pub fn print_out(
        &self,
        fmtstr: &str,
        args: &[(&str, &Option<ColorSpec>)],
    ) -> Result<(), StringError> {
        self.print(&self.outwriter, fmtstr, args, false)
    }

    pub fn println_out(
        &self,
        fmtstr: &str,
        args: &[(&str, &Option<ColorSpec>)],
    ) -> Result<(), StringError> {
        self.print(&self.outwriter, fmtstr, args, true)
    }

    #[allow(dead_code)]
    pub fn print_err(
        &self,
        fmtstr: &str,
        args: &[(&str, &Option<ColorSpec>)],
    ) -> Result<(), StringError> {
        self.print(&self.errwriter, fmtstr, args, false)
    }

    pub fn println_err(
        &self,
        fmtstr: &str,
        args: &[(&str, &Option<ColorSpec>)],
    ) -> Result<(), StringError> {
        self.print(&self.errwriter, fmtstr, args, true)
    }

    fn print(
        &self,
        writer: &BufferWriter,
        fmtstr: &str,
        args: &[(&str, &Option<ColorSpec>)],
        newline: bool,
    ) -> Result<(), StringError> {
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
                            if let Some(&(s, colorspec)) = arg_iter.next() {
                                if !s.is_empty() {
                                    if let Some(ref colorspec) = *colorspec {
                                        buffer.set_color(colorspec).unwrap();
                                    }
                                    buffer.write_all(s.as_bytes()).unwrap();
                                    if colorspec.is_some() {
                                        buffer.reset().unwrap();
                                    }
                                }
                                count += 1;
                            } else {
                                return Err(StringError(format!(
                                    "Not enough arguments (need more than {})",
                                    count
                                )));
                            }
                        }
                        Some('{') => {
                            buffer.write_all(b"{").unwrap();
                        }
                        _ => {
                            return Err(StringError("{{ not closed".to_owned()));
                        }
                    }
                }
                '}' => {
                    let c = char_iter.next();
                    match c {
                        Some('}') => {
                            buffer.write_all(b"}").unwrap();
                        }
                        _ => {
                            return Err(StringError("}} not closed".to_owned()));
                        }
                    }
                }
                c => {
                    let mut buf = [0; 4];
                    buffer
                        .write_all(c.encode_utf8(&mut buf).as_bytes())
                        .unwrap();
                }
            }
            current = char_iter.next();
        }
        if newline {
            buffer.write_all(b"\n").unwrap();
        }
        writer.print(&buffer).unwrap();
        Ok(())
    }
}
