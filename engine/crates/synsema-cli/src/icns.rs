//! Contenedor `.icns` de macOS a partir de PNGs (tanda escritorio, `--bundle` en Mach-O).
//! Formato: `"icns"` + longitud total (u32 BE) + entradas `tipo(4) + longitud(4 BE, incluye
//! los 8 bytes de header) + datos`. Con PNG adentro (aceptado desde 10.7) no hace falta
//! ninguna herramienta de Apple. Sin dependencias.

/// Los tipos PNG por lado (px): 16, 32, 64, 128, 256, 512, 1024.
pub const ICNS_TYPES: [(u32, &[u8; 4]); 7] = [
    (16, b"icp4"),
    (32, b"icp5"),
    (64, b"icp6"),
    (128, b"ic07"),
    (256, b"ic08"),
    (512, b"ic09"),
    (1024, b"ic10"),
];

/// Arma el `.icns` con las entradas `(lado, png)` dadas (las que no tienen tipo se saltan).
pub fn build(entries: &[(u32, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut body: Vec<u8> = Vec::new();
    let mut count = 0usize;
    for (side, png) in entries {
        let Some((_, ty)) = ICNS_TYPES.iter().find(|(s, _)| s == side) else { continue };
        if !png.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(format!(".icns: the {}px image is not a PNG", side));
        }
        body.extend_from_slice(*ty);
        body.extend_from_slice(&((png.len() + 8) as u32).to_be_bytes());
        body.extend_from_slice(png);
        count += 1;
    }
    if count == 0 {
        return Err(".icns: no image with a supported size (16/32/64/128/256/512/1024)".to_string());
    }
    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend_from_slice(b"icns");
    out.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Las entradas `(tipo, datos)` de un `.icns` (para tests y verificación).
#[cfg(test)]
pub fn entries(icns: &[u8]) -> Result<Vec<([u8; 4], Vec<u8>)>, String> {
    if icns.len() < 8 || &icns[..4] != b"icns" {
        return Err("not an .icns file".to_string());
    }
    let total = u32::from_be_bytes(icns[4..8].try_into().unwrap()) as usize;
    if total != icns.len() {
        return Err(".icns: length mismatch".to_string());
    }
    let mut out = Vec::new();
    let mut at = 8;
    while at + 8 <= icns.len() {
        let ty: [u8; 4] = icns[at..at + 4].try_into().unwrap();
        let len = u32::from_be_bytes(icns[at + 4..at + 8].try_into().unwrap()) as usize;
        if len < 8 || at + len > icns.len() {
            return Err(".icns: bad entry length".to_string());
        }
        out.push((ty, icns[at + 8..at + len].to_vec()));
        at += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(tag: &[u8]) -> Vec<u8> {
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        p.extend_from_slice(tag);
        p
    }

    #[test]
    fn icns_round_trips_the_supported_sizes() {
        let icns = build(&[(16, png(b"a")), (512, png(b"bb")), (999, png(b"skip")), (1024, png(b"ccc"))]).unwrap();
        let e = entries(&icns).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(&e[0].0, b"icp4");
        assert_eq!(e[0].1, png(b"a"));
        assert_eq!(&e[1].0, b"ic09");
        assert_eq!(&e[2].0, b"ic10");
        assert_eq!(e[2].1, png(b"ccc"));
        assert!(build(&[(16, b"not png".to_vec())]).is_err());
        assert!(build(&[(999, png(b"x"))]).is_err());
        assert!(entries(b"icns\0\0\0\x03").is_err());
    }
}
