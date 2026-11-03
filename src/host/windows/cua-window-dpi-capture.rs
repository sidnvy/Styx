// Applied only to the pinned Cua 0.36.0 Windows capture module by
// prepare-cua-windows-wgc.py. Keep the mature capture engine and its HWND.
// PrintWindow renders a DPI-unaware target in logical pixels even when the
// caller's bitmap is sized in physical pixels. WGC supplies the target's own
// composited pixels, including when another window covers it. Never resize or
// crop a partial PrintWindow image into an invented successful observation.
fn capture_dpi_unaware_window(hwnd: u64) -> Result<Option<(Vec<u8>, bool, Option<FrameGeometry>)>> {
    use windows::Win32::UI::HiDpi::{
        GetAwarenessFromDpiAwarenessContext, GetWindowDpiAwarenessContext, DPI_AWARENESS_INVALID,
        DPI_AWARENESS_UNAWARE,
    };
    let context = unsafe { GetWindowDpiAwarenessContext(HWND(hwnd as *mut _)) };
    if context == Default::default() {
        bail!("window DPI context unavailable; capture geometry is unproven");
    }
    let awareness = unsafe { GetAwarenessFromDpiAwarenessContext(context) };
    if awareness == DPI_AWARENESS_INVALID {
        bail!("window DPI awareness unavailable; capture geometry is unproven");
    }
    if awareness != DPI_AWARENESS_UNAWARE {
        return Ok(None);
    }
    let (pixels, width, height) = crate::wgc::screenshot_window_via_wgc(hwnd).map_err(|error| {
        anyhow::anyhow!(
            "DPI-unaware window needs compositor capture; no partial GDI or screen-region fallback: {error}"
        )
    })?;
    Ok(Some((
        cua_driver_core::image_utils::encode_bgra_to_png(&pixels, width, height)?,
        false,
        // WGC gives no proven screen origin. Preserve the existing restriction
        // against using this frame as mapped pixel-action evidence.
        None,
    )))
}
