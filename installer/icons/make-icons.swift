// Generates every app icon from one source artwork (PNG with transparency):
//   installer/icons/rezen-1024.png            master, used for the macOS .icns (kept out of the app resources)
//   src/RezenBackup.UI/Assets/rezen-256.png   in-app logo (sidebar, wizard, About)
//   src/RezenBackup.UI/Assets/rezen-tray.png  tray / menu-bar icon (64 px)
//   src/RezenBackup.UI/Assets/rezen.ico       Windows exe, window, taskbar and installer icon (16–256 px)
// Usage: swift installer/icons/make-icons.swift installer/icons/rezen-source.png
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(1)
}

guard CommandLine.arguments.count == 2 else { fail("usage: make-icons.swift <source.png>") }
let sourceURL = URL(fileURLWithPath: CommandLine.arguments[1])
guard let src = CGImageSourceCreateWithURL(sourceURL as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(src, 0, nil) else { fail("cannot read \(sourceURL.path)") }

let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!

// Bounding box of clearly visible pixels (alpha > 40), so faint glow specks don't shrink the artwork.
func visibleBounds(_ img: CGImage) -> CGRect {
    let w = img.width, h = img.height
    var data = [UInt8](repeating: 0, count: w * h * 4)
    let ctx = CGContext(data: &data, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                        space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
    var minX = w, minY = h, maxX = -1, maxY = -1
    for y in 0..<h {
        for x in 0..<w where data[(y * w + x) * 4 + 3] > 40 {
            minX = min(minX, x); maxX = max(maxX, x); minY = min(minY, y); maxY = max(maxY, y)
        }
    }
    guard maxX >= 0 else { fail("source image is fully transparent") }
    return CGRect(x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1)  // top-left origin rows
}

let bounds = visibleBounds(image)
guard let cropped = image.cropping(to: bounds) else { fail("crop failed") }

/// Draws the artwork centred on a transparent square canvas, leaving `margin` (fraction of the side) on each edge.
func render(size: Int, margin: Double) -> CGImage {
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                        space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.interpolationQuality = .high
    let box = Double(size) * (1 - 2 * margin)
    let scale = min(box / Double(cropped.width), box / Double(cropped.height))
    let w = Double(cropped.width) * scale, h = Double(cropped.height) * scale
    ctx.draw(cropped, in: CGRect(x: (Double(size) - w) / 2, y: (Double(size) - h) / 2, width: w, height: h))
    return ctx.makeImage()!
}

func pngData(_ img: CGImage) -> Data {
    let data = NSMutableData()
    let dest = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, img, nil)
    guard CGImageDestinationFinalize(dest) else { fail("PNG encode failed") }
    return data as Data
}

let assets = URL(fileURLWithPath: "src/RezenBackup.UI/Assets")
// Large sizes keep some breathing room (macOS icon grid); small sizes use nearly the full square to stay legible.
func margin(for size: Int) -> Double { size >= 256 ? 0.06 : 0.02 }

try pngData(render(size: 1024, margin: margin(for: 1024))).write(to: URL(fileURLWithPath: "installer/icons/rezen-1024.png"))
try pngData(render(size: 256, margin: margin(for: 256))).write(to: assets.appendingPathComponent("rezen-256.png"))
try pngData(render(size: 64, margin: margin(for: 64))).write(to: assets.appendingPathComponent("rezen-tray.png"))

// ICO with PNG-compressed entries (supported since Windows Vista).
let icoSizes = [16, 24, 32, 48, 64, 128, 256]
let entries = icoSizes.map { pngData(render(size: $0, margin: margin(for: $0))) }
var ico = Data()
func le16(_ v: Int) { ico.append(contentsOf: [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)]) }
func le32(_ v: Int) { le16(v & 0xffff); le16((v >> 16) & 0xffff) }
le16(0); le16(1); le16(icoSizes.count)
var offset = 6 + 16 * icoSizes.count
for (size, png) in zip(icoSizes, entries) {
    ico.append(UInt8(size >= 256 ? 0 : size)); ico.append(UInt8(size >= 256 ? 0 : size))
    ico.append(0); ico.append(0)       // palette, reserved
    le16(1); le16(32)                  // colour planes, bits per pixel
    le32(png.count); le32(offset)
    offset += png.count
}
entries.forEach { ico.append($0) }
try ico.write(to: assets.appendingPathComponent("rezen.ico"))
print("Icons written from \(sourceURL.lastPathComponent) (visible area \(Int(bounds.width))x\(Int(bounds.height)))")
