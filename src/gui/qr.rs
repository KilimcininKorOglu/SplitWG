//! QR decoding for WireGuard `.conf` import.
//!
//! Two sources: an image file picked via `rfd`, and the current system
//! pasteboard (when the user snipped a screenshot with Cmd+Shift+4). Both
//! paths share the same decode pipeline: decode → luma8 → resize if huge →
//! `rqrr::PreparedImage::detect_grids` → first payload → validate that it
//! starts with `[Interface]` so non-WG QR codes are rejected cleanly.

use std::path::Path;

use image::{DynamicImage, GrayImage, ImageReader};

#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error("image io: {0}")]
    Image(#[from] image::ImageError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("clipboard has no image")]
    ClipboardEmpty,
    #[error("qr decode failed")]
    DecodeFailed,
    #[error("not a WireGuard config")]
    NotAConfig,
}

/// Decodes a QR code embedded in an image file. Returns the raw decoded
/// text on success — which the caller should validate as a WG `.conf`.
pub fn decode_from_path(path: &Path) -> Result<String, QrError> {
    log::info!("splitwg: qr: loading image from {:?}", path);
    let img = ImageReader::open(path)?.with_guessed_format()?.decode()?;
    let result = decode_dynamic(img);
    match &result {
        Ok(_) => log::info!("splitwg: qr: QR code detected and decoded"),
        Err(e) => log::warn!("splitwg: qr: decode failed: {}", e),
    }
    result
}

/// Decodes the QR currently on the system pasteboard (PNG or TIFF).
pub fn decode_from_clipboard() -> Result<String, QrError> {
    log::info!("splitwg: qr: reading image from clipboard");
    let bytes = read_clipboard_image_bytes().ok_or_else(|| {
        log::warn!("splitwg: qr: clipboard has no image data");
        QrError::ClipboardEmpty
    })?;
    log::info!("splitwg: qr: clipboard image loaded ({} bytes)", bytes.len());
    let img = image::load_from_memory(&bytes)?;
    let result = decode_dynamic(img);
    match &result {
        Ok(_) => log::info!("splitwg: qr: QR code detected from clipboard"),
        Err(e) => log::warn!("splitwg: qr: clipboard decode failed: {}", e),
    }
    result
}

fn decode_dynamic(img: DynamicImage) -> Result<String, QrError> {
    let luma = downsample_if_huge(img).into_luma8();

    if let Some(payload) = try_decode_luma(&luma) {
        return validate(payload);
    }
    // Phone screenshots occasionally land sideways; try each rotation.
    for rotated in [rotate90(&luma), rotate180(&luma), rotate270(&luma)] {
        if let Some(payload) = try_decode_luma(&rotated) {
            return validate(payload);
        }
    }
    Err(QrError::DecodeFailed)
}

fn try_decode_luma(luma: &GrayImage) -> Option<String> {
    let mut prepared = rqrr::PreparedImage::prepare(luma.clone());
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            return Some(content);
        }
    }
    None
}

fn validate(payload: String) -> Result<String, QrError> {
    let trimmed = payload.trim_start();
    if trimmed.starts_with("[Interface]") {
        Ok(payload)
    } else {
        Err(QrError::NotAConfig)
    }
}

fn downsample_if_huge(img: DynamicImage) -> DynamicImage {
    const MAX_EDGE: u32 = 1280;
    let (w, h) = (img.width(), img.height());
    if w <= MAX_EDGE && h <= MAX_EDGE {
        return img;
    }
    img.resize(MAX_EDGE, MAX_EDGE, image::imageops::FilterType::Triangle)
}

fn rotate90(src: &GrayImage) -> GrayImage {
    image::imageops::rotate90(src)
}

fn rotate180(src: &GrayImage) -> GrayImage {
    image::imageops::rotate180(src)
}

fn rotate270(src: &GrayImage) -> GrayImage {
    image::imageops::rotate270(src)
}

// ---------------------------------------------------------------------------
// Clipboard access (NSPasteboard)
// ---------------------------------------------------------------------------

fn read_clipboard_image_bytes() -> Option<Vec<u8>> {
    use objc2::rc::autoreleasepool;
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::NSString;

    autoreleasepool(|_| {
        let pasteboard = NSPasteboard::generalPasteboard();
        for ty in [
            "public.png",
            "public.tiff",
            "public.jpeg",
            "com.compuserve.gif",
        ] {
            let ns_type = NSString::from_str(ty);
            if let Some(data) = pasteboard.dataForType(&ns_type) {
                return Some(data.to_vec());
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_non_wg_payload() {
        let err = validate("https://example.com".into()).unwrap_err();
        assert!(matches!(err, QrError::NotAConfig));
    }

    #[test]
    fn validate_accepts_interface_prefix() {
        let payload = "[Interface]\nPrivateKey = xxx\n".to_string();
        assert!(validate(payload).is_ok());
    }

    #[test]
    fn validate_tolerates_leading_whitespace() {
        let payload = "\n  [Interface]\nAddress = 10.0.0.2/24\n".to_string();
        assert!(validate(payload).is_ok());
    }
}
