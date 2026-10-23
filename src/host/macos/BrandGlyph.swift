import AppKit
import CoreGraphics

// The supplied light artwork is the canonical glyph. Its white card and
// rounded border are presentation in the JPEG, not part of the brand mark.
func styxBrandGlyph(source: NSImage) -> NSImage? {
    var rect = NSRect(origin: .zero, size: source.size)
    guard let cg = source.cgImage(forProposedRect: &rect, context: nil, hints: nil),
          cg.width >= 16, cg.height >= 16, cg.width <= 4096, cg.height <= 4096 else { return nil }
    let width = cg.width, height = cg.height, rowBytes = width * 4
    var pixels = [UInt8](repeating: 255, count: rowBytes * height)
    let rendered = pixels.withUnsafeMutableBytes { bytes -> Bool in
        guard let context = CGContext(data: bytes.baseAddress, width: width, height: height,
                                      bitsPerComponent: 8, bytesPerRow: rowBytes,
                                      space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return false }
        context.setFillColor(CGColor(gray: 1, alpha: 1)); context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        context.draw(cg, in: CGRect(x: 0, y: 0, width: width, height: height))
        return true
    }
    guard rendered else { return nil }
    func luminance(_ x: Int, _ y: Int) -> Int {
        let offset = y * rowBytes + x * 4
        return (54 * Int(pixels[offset]) + 183 * Int(pixels[offset + 1]) + 19 * Int(pixels[offset + 2])) / 256
    }
    // The source is the approved square icon with its glyph in the central 60%.
    // Search that region so JPEG/background noise and the outer card cannot
    // become an opaque template rectangle. Preserve all interior wave gaps.
    var left = width, right = -1, bottom = height, top = -1
    for y in (height / 5)..<(height * 4 / 5) {
        for x in (width / 5)..<(width * 4 / 5) where luminance(x, y) < 128 {
            left = min(left, x); right = max(right, x); bottom = min(bottom, y); top = max(top, y)
        }
    }
    guard right >= left, top >= bottom else { return nil }
    let glyphWidth = right - left + 1, glyphHeight = top - bottom + 1
    let side = max(glyphWidth, glyphHeight) + 4
    guard let mask = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: side, pixelsHigh: side,
                                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                     isPlanar: false, colorSpaceName: .deviceRGB,
                                     bytesPerRow: side * 4, bitsPerPixel: 32), let bytes = mask.bitmapData else { return nil }
    memset(bytes, 0, side * side * 4)
    let offsetX = (side - glyphWidth) / 2, offsetY = (side - glyphHeight) / 2
    for y in 0..<glyphHeight {
        for x in 0..<glyphWidth {
            let offset = ((y + offsetY) * side + x + offsetX) * 4
            bytes[offset + 3] = UInt8(max(0, (243 - luminance(left + x, bottom + y)) * 255 / 243))
        }
    }
    mask.size = NSSize(width: 18, height: 18)
    let image = NSImage(size: mask.size); image.addRepresentation(mask); image.isTemplate = false
    return image
}

