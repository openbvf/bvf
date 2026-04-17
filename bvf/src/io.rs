use std::io::{Error, ErrorKind, Read};

#[allow(clippy::indexing_slicing)]
pub(crate) fn read_exact_or_less<R: Read>(
    src: &mut R,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut total = 0;
    while total < buf.len() {
        match src.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}
