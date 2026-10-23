// Build-time resource renderer; never launched by the installed App.
import AppKit

func renderBrandIcons() throws {
    guard CommandLine.arguments.count == 4,
          let source = NSImage(contentsOfFile: CommandLine.arguments[1]),
          let glyph = styxBrandGlyph(source: source) else { throw CocoaError(.fileReadCorruptFile) }
    let brand = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    let iconset = URL(fileURLWithPath: CommandLine.arguments[3], isDirectory: true)
    func png(_ size: Int, inset: CGFloat) throws -> Data {
        guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
                                            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                            isPlanar: false, colorSpaceName: .deviceRGB,
                                            bytesPerRow: size * 4, bitsPerPixel: 32),
              let context = NSGraphicsContext(bitmapImageRep: bitmap) else { throw CocoaError(.fileWriteUnknown) }
        bitmap.size = NSSize(width: size, height: size)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        context.imageInterpolation = .high
        NSColor.clear.setFill(); NSRect(x: 0, y: 0, width: size, height: size).fill(using: .copy)
        let margin = CGFloat(size) * inset
        glyph.draw(in: NSRect(x: margin, y: margin, width: CGFloat(size) - margin * 2, height: CGFloat(size) - margin * 2))
        NSGraphicsContext.restoreGraphicsState()
        guard let data = bitmap.representation(using: .png, properties: [:]) else { throw CocoaError(.fileWriteUnknown) }
        return data
    }
    // App icons leave room for the system's own presentation. No baked black
    // tile, white card, border, rounded rectangle or second enclosing mask.
    for size in [16, 32, 128, 256, 512] {
        for scale in [1, 2] {
            let name = "icon_\(size)x\(size)\(scale == 2 ? "@2x" : "").png"
            try png(size * scale, inset: 0.10).write(to: iconset.appendingPathComponent(name), options: .withoutOverwriting)
        }
    }
    try png(512, inset: 0.05).write(to: brand.appendingPathComponent("styx-plugin-icon.png"), options: .withoutOverwriting)
}
do { try renderBrandIcons() }
catch { fputs("Styx brand icon rendering failed\n", stderr); exit(1) }
